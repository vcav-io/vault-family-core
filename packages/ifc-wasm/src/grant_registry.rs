//! In-memory grant registry for tracking issued and received capability grants.

use std::collections::BTreeMap;

use message_envelope::grant::CapabilityGrant;
use message_envelope::EnvelopeError;

const MAX_GRANTS: usize = 256;

/// Whether the grant was issued by or received by this agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantRole {
    Issued,
    Received,
}

/// A stored grant with usage tracking.
pub struct GrantRecord {
    pub grant: CapabilityGrant,
    pub use_count: u32,
    pub role: GrantRole,
}

/// In-memory store for capability grants, keyed by grant_id.
pub struct GrantRegistry {
    records: BTreeMap<String, GrantRecord>,
}

impl GrantRegistry {
    pub fn new() -> Self {
        GrantRegistry {
            records: BTreeMap::new(),
        }
    }

    /// Store a grant that this agent issued. Idempotent: same grant_id is a no-op.
    pub fn store_issued(&mut self, grant: CapabilityGrant) -> Result<(), EnvelopeError> {
        if self.records.contains_key(&grant.grant_id) {
            return Ok(());
        }
        if self.records.len() >= MAX_GRANTS {
            return Err(EnvelopeError::GrantRegistryFull);
        }
        let grant_id = grant.grant_id.clone();
        self.records.insert(
            grant_id,
            GrantRecord {
                grant,
                use_count: 0,
                role: GrantRole::Issued,
            },
        );
        Ok(())
    }

    /// Store a grant that this agent received. Idempotent: same grant_id is a no-op.
    pub fn store_received(&mut self, grant: CapabilityGrant) -> Result<(), EnvelopeError> {
        if self.records.contains_key(&grant.grant_id) {
            return Ok(());
        }
        if self.records.len() >= MAX_GRANTS {
            return Err(EnvelopeError::GrantRegistryFull);
        }
        let grant_id = grant.grant_id.clone();
        self.records.insert(
            grant_id,
            GrantRecord {
                grant,
                use_count: 0,
                role: GrantRole::Received,
            },
        );
        Ok(())
    }

    /// Lookup a grant record by ID.
    #[allow(dead_code)]
    pub fn get(&self, grant_id: &str) -> Option<&GrantRecord> {
        self.records.get(grant_id)
    }

    /// Increment and return the use count for a grant. Fails if at limit.
    pub fn increment_use_count(&mut self, grant_id: &str) -> Result<u32, EnvelopeError> {
        let record = self
            .records
            .get_mut(grant_id)
            .ok_or_else(|| EnvelopeError::GrantNotFound(grant_id.to_string()))?;
        if record.use_count >= record.grant.permissions.max_uses {
            return Err(EnvelopeError::UseLimitExceeded {
                used: record.use_count,
                max: record.grant.permissions.max_uses,
            });
        }
        record.use_count += 1;
        Ok(record.use_count)
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn summary(&self) -> serde_json::Value {
        let issued = self
            .records
            .values()
            .filter(|r| r.role == GrantRole::Issued)
            .count();
        let received = self
            .records
            .values()
            .filter(|r| r.role == GrantRole::Received)
            .count();
        serde_json::json!({
            "total": self.records.len(),
            "issued": issued,
            "received": received,
        })
    }
}
