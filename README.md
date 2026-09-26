# EffectLatch

EffectLatch is an experimental Rust runtime for bounded WebAssembly tools. The source covers attenuated grants, durable external-effect identity, lease-fenced workers, and explicit uncertainty when an external outcome cannot be established.

This public repository contains the product source, database migrations, API schemas, and a configuration example. Development plans, test harnesses, example guests, generated fixtures, machine-specific setup, and verification evidence are kept outside this source snapshot.

The product is **incomplete**. End-to-end acceptance, security testing, benchmarks, clean-environment reproduction, and deployment have not been established. There is no production usage or performance claim.

The Rust toolchain is pinned in `rust-toolchain.toml`. Build available components with `cargo build --workspace --locked`. PostgreSQL is required for the control and store paths. The full development test suite is not part of this minimal public source snapshot.

Original code is MIT-licensed. Third-party dependencies retain their own licenses.
