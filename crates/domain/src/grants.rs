//! Pure grant checks. Callers must lock the complete ancestry in PostgreSQL and
//! use database time; this module is never an in-memory authorization cache.
use crate::types::alias;
use std::collections::BTreeSet;
use uuid::Uuid;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Authority {
    pub actions: BTreeSet<String>,
    pub destinations: BTreeSet<String>,
    pub projects: BTreeSet<String>,
    pub expires_at_ms: i64,
    pub max_effects: u64,
}
#[derive(Clone, Debug)]
pub struct Grant {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub parent_id: Option<Uuid>,
    pub depth: u8,
    pub authority: Authority,
    pub used_effects: u64,
    pub revoked: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum GrantError {
    #[error("invalid authority")]
    Invalid,
    #[error("authority escalation")]
    Escalation,
    #[error("invalid grant ancestry")]
    Ancestry,
    #[error("grant expired or revoked")]
    Inactive,
    #[error("grant budget exhausted")]
    Exhausted,
    #[error("action or resource denied")]
    Denied,
}
impl Authority {
    pub fn validate_shape(&self) -> Result<(), GrantError> {
        if !(1..=100).contains(&self.max_effects) {
            return Err(GrantError::Invalid);
        }
        if self.actions.len() != 1 || !self.actions.contains("ticket.create") {
            return Err(GrantError::Invalid);
        }
        for set in [&self.destinations, &self.projects] {
            if set.is_empty() || set.len() > 16 || !set.iter().all(|v| alias(v)) {
                return Err(GrantError::Invalid);
            }
        }
        Ok(())
    }
    pub fn validate(&self, now_ms: i64) -> Result<(), GrantError> {
        self.validate_shape()?;
        let ttl = self
            .expires_at_ms
            .checked_sub(now_ms)
            .ok_or(GrantError::Invalid)?;
        if ttl <= 0 || ttl > 86_400_000 {
            return Err(GrantError::Invalid);
        }
        Ok(())
    }
    pub fn attenuates(&self, parent: &Self) -> bool {
        self.actions.is_subset(&parent.actions)
            && self.destinations.is_subset(&parent.destinations)
            && self.projects.is_subset(&parent.projects)
            && self.expires_at_ms <= parent.expires_at_ms
            && self.max_effects <= parent.max_effects
    }
}

/// Validate structural identity and liveness, independently of remaining budget.
/// Exhausted ancestry may still be inspected or replay a committed effect.
pub fn validate_chain(chain: &[Grant], tenant: Uuid, now_ms: i64) -> Result<(), GrantError> {
    if chain.is_empty() || chain.len() > 5 {
        return Err(GrantError::Ancestry);
    }
    let mut seen = BTreeSet::new();
    for (index, grant) in chain.iter().enumerate() {
        if grant.tenant_id != tenant
            || grant.depth as usize != index
            || !seen.insert(grant.id)
            || grant.parent_id != index.checked_sub(1).map(|i| chain[i].id)
        {
            return Err(GrantError::Ancestry);
        }
        if grant.revoked || grant.authority.expires_at_ms <= now_ms {
            return Err(GrantError::Inactive);
        }
        if grant.used_effects > grant.authority.max_effects {
            return Err(GrantError::Invalid);
        }
        if index > 0 && !grant.authority.attenuates(&chain[index - 1].authority) {
            return Err(GrantError::Escalation);
        }
    }
    Ok(())
}
pub fn validate_child(
    child: &Authority,
    ancestry: &[Grant],
    tenant: Uuid,
    now_ms: i64,
) -> Result<(), GrantError> {
    child.validate(now_ms)?;
    validate_chain(ancestry, tenant, now_ms)?;
    if ancestry.len() >= 5 {
        return Err(GrantError::Ancestry);
    }
    if !ancestry.iter().all(|g| child.attenuates(&g.authority)) {
        return Err(GrantError::Escalation);
    }
    Ok(())
}

/// Return an all-ancestor reservation plan without mutating partial state.
/// The store applies this once per new logical effect inside its locked transaction;
/// replay/retry must instead use the existing unique effect_reservations rows.
pub fn reservation_plan(
    chain: &[Grant],
    tenant: Uuid,
    now_ms: i64,
    action: &str,
    destination: &str,
    project: &str,
) -> Result<Vec<(Uuid, u64)>, GrantError> {
    validate_chain(chain, tenant, now_ms)?;
    let mut plan = Vec::with_capacity(chain.len());
    for grant in chain {
        let authority = &grant.authority;
        if !authority.actions.contains(action)
            || !authority.destinations.contains(destination)
            || !authority.projects.contains(project)
        {
            return Err(GrantError::Denied);
        }
        if grant.used_effects >= authority.max_effects {
            return Err(GrantError::Exhausted);
        }
        plan.push((
            grant.id,
            grant
                .used_effects
                .checked_add(1)
                .ok_or(GrantError::Exhausted)?,
        ));
    }
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn root() -> Grant {
        Grant {
            id: Uuid::from_u128(1),
            tenant_id: Uuid::from_u128(2),
            parent_id: None,
            depth: 0,
            authority: Authority {
                actions: BTreeSet::from(["ticket.create".into()]),
                destinations: BTreeSet::from(["tickets-idem".into()]),
                projects: BTreeSet::from(["DEMO".into()]),
                expires_at_ms: 1000,
                max_effects: 3,
            },
            used_effects: 0,
            revoked: false,
        }
    }
    #[test]
    fn exhausted_root_cannot_be_multiplied_by_fresh_children() {
        let mut parent = root();
        parent.used_effects = 3;
        for id in 3..11 {
            let mut child = root();
            child.id = Uuid::from_u128(id);
            child.parent_id = Some(parent.id);
            child.depth = 1;
            assert_eq!(
                reservation_plan(
                    &[parent.clone(), child],
                    parent.tenant_id,
                    1,
                    "ticket.create",
                    "tickets-idem",
                    "DEMO"
                ),
                Err(GrantError::Exhausted)
            );
        }
    }
    #[test]
    fn resource_and_expiry_escalation_are_denied() {
        let parent = root();
        let mut child = parent.authority.clone();
        child.projects.insert("PRIVATE".into());
        assert_eq!(
            validate_child(&child, std::slice::from_ref(&parent), parent.tenant_id, 1),
            Err(GrantError::Escalation)
        );
        child = parent.authority.clone();
        child.expires_at_ms += 1;
        assert_eq!(
            validate_child(&child, std::slice::from_ref(&parent), parent.tenant_id, 1),
            Err(GrantError::Escalation)
        );
    }
    #[test]
    fn reservation_includes_every_ancestor_without_mutating_inputs() {
        let parent = root();
        let mut child = parent.clone();
        child.id = Uuid::from_u128(3);
        child.parent_id = Some(parent.id);
        child.depth = 1;
        let chain = [parent.clone(), child.clone()];
        assert_eq!(
            reservation_plan(
                &chain,
                parent.tenant_id,
                1,
                "ticket.create",
                "tickets-idem",
                "DEMO"
            ),
            Ok(vec![(parent.id, 1), (child.id, 1)])
        );
        assert_eq!(chain[0].used_effects, 0);
        assert_eq!(
            reservation_plan(
                &chain,
                parent.tenant_id,
                1000,
                "ticket.create",
                "tickets-idem",
                "DEMO"
            ),
            Err(GrantError::Inactive)
        );
    }
}
