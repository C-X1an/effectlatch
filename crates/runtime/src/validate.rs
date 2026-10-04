use std::collections::BTreeMap;
use wasmparser::{
    CompositeInnerType, Encoding, ExternalKind, FuncType, Parser, Payload, TypeRef, ValType,
    Validator, WasmFeatures,
};

#[derive(Debug, thiserror::Error)]
#[error("module does not implement the EffectLatch ABI v1")]
pub struct InvalidModule;

fn expected(name: &str) -> Option<(&'static [ValType], &'static [ValType])> {
    const NONE: &[ValType] = &[];
    const I32: &[ValType] = &[ValType::I32];
    const TWO_I32: &[ValType] = &[ValType::I32, ValType::I32];
    const FOUR_I32: &[ValType] = &[ValType::I32, ValType::I32, ValType::I32, ValType::I32];
    match name {
        "input_len" => Some((NONE, I32)),
        "input_read" | "output_write" | "log" => Some((TWO_I32, I32)),
        "effect_call" => Some((FOUR_I32, I32)),
        _ => None,
    }
}

fn signature(types: &[FuncType], index: u32) -> Result<&FuncType, InvalidModule> {
    types.get(index as usize).ok_or(InvalidModule)
}

/// Validate core Wasm and the complete ABI surface before persistence. Runtime
/// construction repeats this validation before execution as a defense in depth.
pub fn validate(bytes: &[u8]) -> Result<(), InvalidModule> {
    if bytes.is_empty() || bytes.len() > effectlatch_domain::MODULE_BYTES {
        return Err(InvalidModule);
    }
    // Explicit core WebAssembly 2.0 allowlist. This admits ordinary compiler
    // code (bulk memory, SIMD, multi-value) while excluding threads, shared
    // memory, memory64, GC, tail calls, components and future default features.
    Validator::new_with_features(WasmFeatures::WASM2)
        .validate_all(bytes)
        .map_err(|_| InvalidModule)?;

    let mut types = Vec::new();
    let mut imports = BTreeMap::new();
    let mut imported_functions = 0_u32;
    let mut local_type_indices = Vec::new();
    let mut memories = 0_u32;
    let mut globals = 0_u32;
    let mut code_bodies = 0_u32;
    let mut run_export = None;
    let mut memory_export = None;
    for payload in Parser::new(0).parse_all(bytes) {
        match payload.map_err(|_| InvalidModule)? {
            Payload::Version {
                encoding: Encoding::Module,
                ..
            } => {}
            Payload::Version { .. } => return Err(InvalidModule),
            Payload::TypeSection(reader) => {
                for group in reader {
                    for subtype in group.map_err(|_| InvalidModule)?.into_types() {
                        match subtype.composite_type.inner {
                            CompositeInnerType::Func(function) if types.len() < 1024 => {
                                types.push(function)
                            }
                            _ => return Err(InvalidModule),
                        }
                    }
                }
            }
            Payload::ImportSection(reader) => {
                for import in reader {
                    let import = import.map_err(|_| InvalidModule)?;
                    let TypeRef::Func(type_index) = import.ty else {
                        return Err(InvalidModule);
                    };
                    if import.module != "effectlatch_v1"
                        || expected(import.name).is_none()
                        || imports.insert(import.name, type_index).is_some()
                    {
                        return Err(InvalidModule);
                    }
                    imported_functions = imported_functions.checked_add(1).ok_or(InvalidModule)?;
                }
            }
            Payload::FunctionSection(reader) => {
                for index in reader {
                    if local_type_indices.len() >= 1024 {
                        return Err(InvalidModule);
                    }
                    local_type_indices.push(index.map_err(|_| InvalidModule)?);
                }
            }
            Payload::MemorySection(reader) => {
                for memory in reader {
                    let memory = memory.map_err(|_| InvalidModule)?;
                    memories = memories.checked_add(1).ok_or(InvalidModule)?;
                    if memory.memory64
                        || memory.shared
                        || memory.page_size_log2.is_some()
                        || memory.initial > 1024
                        || memory.maximum.is_none_or(|maximum| maximum > 1024)
                    {
                        return Err(InvalidModule);
                    }
                }
            }
            // The v1 compiler allowance covers ordinary local i32/i64 globals
            // (such as a stack pointer), not tables or indirect-call surfaces.
            Payload::GlobalSection(reader) => {
                for global in reader {
                    let global = global.map_err(|_| InvalidModule)?;
                    globals = globals.checked_add(1).ok_or(InvalidModule)?;
                    if globals > 32
                        || !matches!(global.ty.content_type, ValType::I32 | ValType::I64)
                    {
                        return Err(InvalidModule);
                    }
                }
            }
            Payload::TableSection(_) | Payload::ElementSection(_) => return Err(InvalidModule),
            Payload::ExportSection(reader) => {
                for export in reader {
                    let export = export.map_err(|_| InvalidModule)?;
                    match (export.name, export.kind) {
                        ("run", ExternalKind::Func)
                            if run_export.replace(export.index).is_none() => {}
                        ("memory", ExternalKind::Memory)
                            if memory_export.replace(export.index).is_none() => {}
                        _ => return Err(InvalidModule),
                    }
                }
            }
            Payload::StartSection { .. } => return Err(InvalidModule),
            // No executable surface beyond the bounded local function bodies.
            Payload::CodeSectionStart { count, .. } if count <= 1024 => {}
            Payload::CodeSectionEntry(_) => {
                code_bodies = code_bodies.checked_add(1).ok_or(InvalidModule)?;
                if code_bodies > 1024 {
                    return Err(InvalidModule);
                }
            }
            Payload::DataSection(reader) if reader.count() <= 256 => {}
            Payload::DataCountSection { count, .. } if count <= 256 => {}
            Payload::CustomSection(_) | Payload::End(_) => {}
            _ => return Err(InvalidModule),
        }
    }
    if imports.len() != 5 || memories != 1 || memory_export != Some(0) {
        return Err(InvalidModule);
    }
    for (name, type_index) in imports {
        let (params, results) = expected(name).ok_or(InvalidModule)?;
        let ty = signature(&types, type_index)?;
        if ty.params() != params || ty.results() != results {
            return Err(InvalidModule);
        }
    }
    let run_index = run_export.ok_or(InvalidModule)?;
    let local_index = run_index
        .checked_sub(imported_functions)
        .ok_or(InvalidModule)?;
    let run_type_index = *local_type_indices
        .get(local_index as usize)
        .ok_or(InvalidModule)?;
    let run_type = signature(&types, run_type_index)?;
    if !run_type.params().is_empty() || run_type.results() != [ValType::I32] {
        return Err(InvalidModule);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate;

    fn source(change: &str) -> String {
        format!(
            r#"(module
                (import "effectlatch_v1" "input_len" (func $input_len (result i32)))
                (import "effectlatch_v1" "input_read" (func $input_read (param i32 i32) (result i32)))
                (import "effectlatch_v1" "effect_call" (func $effect_call (param i32 i32 i32 i32) (result i32)))
                (import "effectlatch_v1" "output_write" (func $output_write (param i32 i32) (result i32)))
                (import "effectlatch_v1" "log" (func $log (param i32 i32) (result i32)))
                (memory (export "memory") 1 1024)
                (func (export "run") (result i32) i32.const 0)
                {change})"#,
        )
    }
    fn module(change: &str) -> Vec<u8> {
        wat::parse_str(source(change)).unwrap()
    }

    #[test]
    fn accepts_only_the_bounded_five_import_abi() {
        assert!(validate(&module("")).is_ok());
        assert!(validate(&module(r#"(func (export "extra"))"#)).is_err());
        assert!(validate(&module("(func $start) (start $start)")).is_err());
        assert!(validate(&module("(table 1 funcref)")).is_err());
        let unknown = module("");
        let unknown = unknown
            .windows(b"input_len".len())
            .position(|window| window == b"input_len")
            .map(|offset| {
                let mut changed = unknown.clone();
                changed[offset..offset + b"input_len".len()].copy_from_slice(b"input_bad");
                changed
            })
            .unwrap();
        assert!(validate(&unknown).is_err());
    }

    #[test]
    fn rejects_ambient_imports_and_signature_drift() {
        for extra in [
            r#"(import "wasi_snapshot_preview1" "fd_write" (func (param i32 i32 i32 i32) (result i32)))"#,
            r#"(import "effectlatch_v1" "input_len" (func (result i32)))"#,
            r#"(import "effectlatch_v1" "foreign_memory" (memory 1 1))"#,
            r#"(import "effectlatch_v1" "foreign_table" (table 1 funcref))"#,
            r#"(import "effectlatch_v1" "foreign_global" (global i32))"#,
        ] {
            let hostile = source("").replace(
                r#"(memory (export "memory") 1 1024)"#,
                &format!("{extra}\n(memory (export \"memory\") 1 1024)"),
            );
            assert!(
                validate(&wat::parse_str(hostile).unwrap()).is_err(),
                "accepted {extra}"
            );
        }
        let missing = source("").replace(
            r#"(import "effectlatch_v1" "log" (func $log (param i32 i32) (result i32)))"#,
            "",
        );
        assert!(validate(&wat::parse_str(missing).unwrap()).is_err());
        let wrong = source("").replace(
            r#"(func $input_len (result i32))"#,
            r#"(func $input_len (param i32) (result i32))"#,
        );
        assert!(validate(&wat::parse_str(wrong).unwrap()).is_err());
    }

    #[test]
    fn rejects_unsupported_memory_and_component_forms() {
        for memory in [
            r#"(memory (export "memory") 1 1024 shared)"#,
            r#"(memory (export "memory") i64 1 1024)"#,
            r#"(memory (export "memory") 1)"#,
            r#"(memory (export "memory") 1025 1025)"#,
        ] {
            let hostile = source("").replace(r#"(memory (export "memory") 1 1024)"#, memory);
            assert!(validate(&wat::parse_str(hostile).unwrap()).is_err());
        }
        assert!(validate(&module("(memory 1 1)")).is_err());
        assert!(validate(&wat::parse_str("(component)").unwrap()).is_err());
    }
}
