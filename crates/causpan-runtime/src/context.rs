//! Trusted request registration and explicit multi-parent context joins.
use serde_json::{json, Value};
use std::{
    collections::{BTreeSet, HashSet},
    fs::{File, OpenOptions},
    io::{self, Write},
    path::Path,
    sync::{Arc, Mutex},
};

/// A context can only be created by its registry. Clone it at an explicit handoff.
#[derive(Clone)]
pub struct CausalContext {
    namespace: Arc<()>,
    tag: u64,
    roots: BTreeSet<u64>,
}

impl CausalContext {
    /// Instrument an async future with this span; do not hold an entered guard
    /// across `.await`. For synchronous work, use the span's `in_scope` method.
    pub fn span(&self) -> tracing::Span {
        tracing::info_span!(parent: None, "causpan.request", causpan_context = self.tag)
    }
}

struct RegistryState {
    sink: File,
    next: u64,
    request_ids: HashSet<String>,
}

/// One registry per captured session. The caller is the trusted transport adapter,
/// never a client-provided context identifier. Records are retained for the session.
pub struct ContextRegistry {
    namespace: Arc<()>,
    state: Mutex<RegistryState>,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

impl ContextRegistry {
    pub fn new(path: impl AsRef<Path>) -> io::Result<Self> {
        Ok(Self {
            namespace: Arc::new(()),
            state: Mutex::new(RegistryState {
                sink: OpenOptions::new().write(true).create_new(true).open(path)?,
                next: 1,
                request_ids: HashSet::new(),
            }),
        })
    }

    pub fn request(&self, rpc_id: Value, tool: &str) -> io::Result<CausalContext> {
        if !(rpc_id.is_string() || rpc_id.is_i64() || rpc_id.is_u64()) {
            return Err(invalid("MCP request ID must be a string or integer"));
        }
        let mut state = self.state.lock().expect("Causpan registry poisoned");
        if !state.request_ids.insert(rpc_id.to_string()) {
            return Err(invalid("MCP request ID reused within session"));
        }
        let tag = state.next;
        state.next = tag
            .checked_add(1)
            .ok_or_else(|| invalid("context IDs exhausted"))?;
        writeln!(
            state.sink,
            "{}",
            json!({"kind":"request","context":tag,
            "rpc_id":rpc_id,"method":"tools/call","tool":tool})
        )?;
        Ok(CausalContext {
            namespace: self.namespace.clone(),
            tag,
            roots: [tag].into(),
        })
    }

    /// Join only the actual contributors to shared work. This is an explicit
    /// provenance assertion by the batching adapter, not inferred data lineage.
    pub fn join(&self, parents: &[CausalContext]) -> io::Result<CausalContext> {
        if parents.is_empty() {
            return Err(invalid("a join requires at least one parent"));
        }
        let mut roots = BTreeSet::new();
        for parent in parents {
            if !Arc::ptr_eq(&parent.namespace, &self.namespace) {
                return Err(invalid("cannot join contexts from different sessions"));
            }
            roots.extend(parent.roots.iter().copied());
        }
        let mut state = self.state.lock().expect("Causpan registry poisoned");
        let tag = state.next;
        state.next = tag
            .checked_add(1)
            .ok_or_else(|| invalid("context IDs exhausted"))?;
        writeln!(
            state.sink,
            "{}",
            json!({"kind":"join","context":tag,"parents":roots})
        )?;
        Ok(CausalContext {
            namespace: self.namespace.clone(),
            tag,
            roots,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn joins_flatten_deduplicate_and_reject_foreign_sessions() {
        let path = crate::tests::temp_path();
        let other_path = crate::tests::temp_path();
        let registry = ContextRegistry::new(&path).unwrap();
        let other = ContextRegistry::new(&other_path).unwrap();
        let a = registry.request(json!(1), "read").unwrap();
        let b = registry.request(json!("1"), "read").unwrap();
        assert!(registry.request(json!(1), "read").is_err());
        assert!(registry.request(json!(null), "read").is_err());
        let joined = registry.join(&[a.clone(), b.clone()]).unwrap();
        let nested = registry.join(&[joined, a]).unwrap();
        assert_eq!(nested.roots, [1, 2].into());
        assert!(registry.join(&[]).is_err());
        assert!(other.join(&[b]).is_err());
        let rows: Vec<Value> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(rows.len(), 4);
        assert_eq!(rows[3]["parents"], json!([1, 2]));
        std::fs::remove_file(path).unwrap();
        std::fs::remove_file(other_path).unwrap();
    }
}
