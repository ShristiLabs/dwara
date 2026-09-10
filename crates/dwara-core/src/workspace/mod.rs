//! Workspaces, RBAC, and audit logging (DW-067, Enterprise).
//!
//! Tenant namespaces (workspaces), admin RBAC roles, and immutable
//! audit log shipping.
//!
//! ## Design (section 5-Platform)
//!
//! - **Workspaces:** tenant namespaces that partition the config
//!   space. Each workspace owns its own routes, services, upstreams,
//!   consumers, and policies. Cross-workspace access is denied by
//!   default.
//! - **RBAC:** role-based access control for the admin API. Roles
//!   reuse the same vocabulary as the M1 admin mTLS identity model
//!   (the client certificate is the principal; roles are assigned to
//!   principals). A role grants a set of permissions (read, write,
//!   admin) on a workspace (or all workspaces).
//! - **Audit log:** every admin API change records the acting
//!   principal, the action, the before/after state, and a timestamp.
//!   The log is append-only/immutable -- not just an event name.
//!
//! ## Persistence (SCALE-05, #184)
//!
//! When a [`crate::state::StateStore`] is attached, the manager
//! persists every mutation (workspace create/delete, role add,
//! role assignment, audit append) to the store's `workspaces`,
//! `rbac_roles`, `rbac_principals`, and `workspace_audit` tables
//! (migration 008). The in-memory `RwLock<HashMap>` remains the hot
//! read path; the store is the durable backing. On startup the
//! manager loads the full state from the store (seeding the
//! `default` workspace if the table is empty). Without a store the
//! manager runs in-memory only (the pre-#184 behavior).
//!
//! ## Feature gate
//!
//! The `enterprise` cargo feature must be enabled. Without it, the
//! module is not compiled and the gateway runs in single-workspace
//! mode (the default OSS behavior).

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};

use crate::state::store::StateStore;

/// A workspace: a tenant namespace that partitions the config space.
///
/// Each workspace owns its own routes, services, upstreams, consumers,
/// and policies. Cross-workspace access is denied by default.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Workspace {
    /// The workspace name (unique, immutable).
    pub name: String,
    /// A human-readable description.
    pub description: String,
    /// Whether the workspace is active (inactive workspaces are
    /// excluded from routing).
    pub active: bool,
}

/// An RBAC role: a named set of permissions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Role {
    /// The role name.
    pub name: String,
    /// The permissions granted by this role.
    pub permissions: Vec<Permission>,
}

/// A permission: an action on a resource.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Permission {
    /// The action: "read", "write", or "admin".
    pub action: Action,
    /// The resource: a workspace name, or "*" for all workspaces.
    pub workspace: String,
}

/// The action a permission grants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Action {
    /// Read access (GET on admin API).
    Read,
    /// Write access (PATCH on admin API).
    Write,
    /// Admin access (full control, including workspace management).
    Admin,
}

impl Action {
    /// Whether this action implies another (Admin > Write > Read).
    pub fn implies(self, other: Action) -> bool {
        matches!(
            (self, other),
            (Action::Admin, _)
                | (Action::Write, Action::Write)
                | (Action::Write, Action::Read)
                | (Action::Read, Action::Read)
        )
    }

    /// The string representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Read => "read",
            Action::Write => "write",
            Action::Admin => "admin",
        }
    }
}

/// A principal: an authenticated admin API caller.
///
/// The principal identity comes from the mTLS client certificate
/// (the M1 admin identity model). The principal is assigned one or
/// more roles, which grant permissions on workspaces.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal {
    /// The principal identity (the mTLS client certificate subject
    /// CN, or a configured identity name).
    pub identity: String,
    /// The roles assigned to this principal.
    pub roles: Vec<String>,
}

/// An audit log entry: records an admin API change.
///
/// The audit log is append-only/immutable. Every admin API change
/// records the acting principal, the action, the before/after state,
/// and a timestamp.
#[derive(Clone, Debug)]
pub struct AuditEntry {
    /// Monotonically assigned sequence number.
    pub seq: u64,
    /// The time of the change (Unix epoch milliseconds).
    pub timestamp_ms: u64,
    /// The acting principal.
    pub principal: String,
    /// The action performed (e.g. "config.patch", "workspace.create").
    pub action: String,
    /// The workspace affected (or "global" for global changes).
    pub workspace: String,
    /// The before state (JSON, None for creations).
    pub before: Option<String>,
    /// The after state (JSON, None for deletions).
    pub after: Option<String>,
    /// The request ID (correlation handle).
    pub request_id: String,
}

/// The workspace manager: holds workspaces, roles, principals, and
/// the audit log. When a [`StateStore`] is attached, every mutation
/// is persisted (SCALE-05, #184); the in-memory maps remain the hot
/// read path.
pub struct WorkspaceManager {
    workspaces: RwLock<HashMap<String, Workspace>>,
    roles: RwLock<HashMap<String, Role>>,
    principals: RwLock<HashMap<String, Principal>>,
    audit_log: RwLock<Vec<AuditEntry>>,
    audit_seq: RwLock<u64>,
    /// Optional durable backing store. When present, every mutation
    /// is persisted here and the initial state is loaded from it on
    /// construction.
    store: Option<Arc<StateStore>>,
}

impl WorkspaceManager {
    /// Create a new workspace manager with a single default workspace
    /// (the OSS behavior). No persistent store is attached.
    pub fn new() -> Self {
        Self::with_store(None)
    }

    /// Create a workspace manager backed by a persistent store
    /// (SCALE-05, #184). The initial state (workspaces, roles,
    /// principals) is loaded from the store; the `default` workspace
    /// is seeded if the table is empty. Every subsequent mutation is
    /// persisted. Without a store (`None`), the manager runs
    /// in-memory only (the pre-#184 behavior).
    pub fn with_store(store: Option<Arc<StateStore>>) -> Self {
        let mgr = Self {
            workspaces: RwLock::new(HashMap::new()),
            roles: RwLock::new(HashMap::new()),
            principals: RwLock::new(HashMap::new()),
            audit_log: RwLock::new(Vec::new()),
            audit_seq: RwLock::new(0),
            store,
        };
        if let Err(err) = mgr.load_from_store() {
            tracing::warn!(
                code = "workspace_store_load_failed",
                "failed to load workspace state from store ({err}); \
                 starting with in-memory defaults"
            );
        }
        mgr
    }

    /// Load workspaces, roles, and principals from the store into
    /// the in-memory maps. Seeds the `default` workspace if the table
    /// is empty. The audit log is NOT loaded into memory (it can be
    /// large; queries go to the store directly).
    fn load_from_store(&self) -> Result<(), String> {
        let store = match &self.store {
            Some(s) => s,
            None => {
                // No store: seed the default workspace in-memory.
                let mut workspaces = self.workspaces.write().unwrap();
                workspaces.insert(
                    "default".to_string(),
                    Workspace {
                        name: "default".to_string(),
                        description: "Default workspace".to_string(),
                        active: true,
                    },
                );
                return Ok(());
            }
        };

        let rows = store
            .list_workspace_rows()
            .map_err(|e| format!("list workspaces: {e}"))?;

        let mut workspaces = self.workspaces.write().unwrap();
        if rows.is_empty() {
            // Seed the default workspace and persist it.
            let default = Workspace {
                name: "default".to_string(),
                description: "Default workspace".to_string(),
                active: true,
            };
            store
                .upsert_workspace(&default.name, &default.description, default.active)
                .map_err(|e| format!("seed default workspace: {e}"))?;
            workspaces.insert(default.name.clone(), default);
        } else {
            for row in rows {
                workspaces.insert(
                    row.name.clone(),
                    Workspace {
                        name: row.name,
                        description: row.description,
                        active: row.active,
                    },
                );
            }
        }
        drop(workspaces);

        // Load roles.
        let role_rows = store
            .list_role_rows()
            .map_err(|e| format!("list roles: {e}"))?;
        let mut roles = self.roles.write().unwrap();
        for row in role_rows {
            let perms = decode_permissions(&row.permissions_json);
            roles.insert(
                row.name.clone(),
                Role {
                    name: row.name,
                    permissions: perms,
                },
            );
        }
        drop(roles);

        // Load principals.
        let principal_rows = store
            .list_principal_rows()
            .map_err(|e| format!("list principals: {e}"))?;
        let mut principals = self.principals.write().unwrap();
        for row in principal_rows {
            let role_names = decode_role_names(&row.roles_json);
            principals.insert(
                row.identity.clone(),
                Principal {
                    identity: row.identity,
                    roles: role_names,
                },
            );
        }
        Ok(())
    }

    /// Check if a principal has a permission.
    pub fn check_permission(
        &self,
        principal_identity: &str,
        action: Action,
        workspace: &str,
    ) -> bool {
        let principals = self.principals.read().unwrap();
        let roles = self.roles.read().unwrap();

        let principal = match principals.get(principal_identity) {
            Some(p) => p,
            None => return false,
        };

        for role_name in &principal.roles {
            if let Some(role) = roles.get(role_name) {
                for perm in &role.permissions {
                    if perm.action.implies(action)
                        && (perm.workspace == "*" || perm.workspace == workspace)
                    {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Create a workspace.
    pub fn create_workspace(
        &self,
        principal: &str,
        workspace: Workspace,
        request_id: &str,
    ) -> Result<(), String> {
        if !self.check_permission(principal, Action::Admin, "global") {
            return Err("permission denied: admin required to create workspaces".to_string());
        }

        let mut workspaces = self.workspaces.write().unwrap();
        if workspaces.contains_key(&workspace.name) {
            return Err(format!("workspace '{}' already exists", workspace.name));
        }

        let after =
            serde_json::to_string(&workspace).map_err(|e| format!("serialize workspace: {e}"))?;

        // Persist before mutating in-memory state (fail-closed: if
        // the store write fails, the workspace is not created).
        if let Some(store) = &self.store {
            store
                .upsert_workspace(&workspace.name, &workspace.description, workspace.active)
                .map_err(|e| format!("persist workspace: {e}"))?;
        }

        workspaces.insert(workspace.name.clone(), workspace);

        self.append_audit(AuditEntry {
            seq: 0, // assigned by append_audit
            timestamp_ms: now_unix_ms(),
            principal: principal.to_string(),
            action: "workspace.create".to_string(),
            workspace: workspace_name(&workspaces, &after),
            before: None,
            after: Some(after),
            request_id: request_id.to_string(),
        });

        Ok(())
    }

    /// Delete a workspace.
    pub fn delete_workspace(
        &self,
        principal: &str,
        workspace_name: &str,
        request_id: &str,
    ) -> Result<(), String> {
        if workspace_name == "default" {
            return Err("cannot delete the default workspace".to_string());
        }
        if !self.check_permission(principal, Action::Admin, "global") {
            return Err("permission denied: admin required to delete workspaces".to_string());
        }

        let mut workspaces = self.workspaces.write().unwrap();
        let workspace = workspaces
            .remove(workspace_name)
            .ok_or_else(|| format!("workspace '{}' not found", workspace_name))?;

        let before =
            serde_json::to_string(&workspace).map_err(|e| format!("serialize workspace: {e}"))?;

        // Persist the deletion.
        if let Some(store) = &self.store {
            store
                .delete_workspace_row(workspace_name)
                .map_err(|e| format!("persist workspace delete: {e}"))?;
        }

        self.append_audit(AuditEntry {
            seq: 0,
            timestamp_ms: now_unix_ms(),
            principal: principal.to_string(),
            action: "workspace.delete".to_string(),
            workspace: workspace_name.to_string(),
            before: Some(before),
            after: None,
            request_id: request_id.to_string(),
        });

        Ok(())
    }

    /// List all workspaces.
    pub fn list_workspaces(&self) -> Vec<Workspace> {
        let workspaces = self.workspaces.read().unwrap();
        workspaces.values().cloned().collect()
    }

    /// Get a workspace by name.
    pub fn get_workspace(&self, name: &str) -> Option<Workspace> {
        let workspaces = self.workspaces.read().unwrap();
        workspaces.get(name).cloned()
    }

    /// Assign a role to a principal.
    pub fn assign_role(
        &self,
        principal_identity: &str,
        role_name: &str,
        request_id: &str,
    ) -> Result<(), String> {
        let roles = self.roles.read().unwrap();
        if !roles.contains_key(role_name) {
            return Err(format!("role '{}' not found", role_name));
        }
        drop(roles);

        let mut principals = self.principals.write().unwrap();
        let principal = principals
            .entry(principal_identity.to_string())
            .or_insert_with(|| Principal {
                identity: principal_identity.to_string(),
                roles: Vec::new(),
            });

        if principal.roles.contains(&role_name.to_string()) {
            return Ok(()); // Already assigned.
        }

        principal.roles.push(role_name.to_string());
        let roles_json = encode_role_names(&principal.roles);

        // Persist.
        if let Some(store) = &self.store {
            store
                .upsert_principal(principal_identity, &roles_json)
                .map_err(|e| format!("persist principal: {e}"))?;
        }

        self.append_audit(AuditEntry {
            seq: 0,
            timestamp_ms: now_unix_ms(),
            principal: principal_identity.to_string(),
            action: "role.assign".to_string(),
            workspace: "global".to_string(),
            before: None,
            after: Some(format!("{{\"role\":\"{role_name}\"}}")),
            request_id: request_id.to_string(),
        });

        Ok(())
    }

    /// Add a role definition.
    pub fn add_role(&self, role: Role) -> Result<(), String> {
        let mut roles = self.roles.write().unwrap();
        if roles.contains_key(&role.name) {
            return Err(format!("role '{}' already exists", role.name));
        }

        let perms_json = encode_permissions(&role.permissions);

        // Persist.
        if let Some(store) = &self.store {
            store
                .upsert_role(&role.name, &perms_json)
                .map_err(|e| format!("persist role: {e}"))?;
        }

        roles.insert(role.name.clone(), role);
        Ok(())
    }

    /// Get a principal.
    pub fn get_principal(&self, identity: &str) -> Option<Principal> {
        let principals = self.principals.read().unwrap();
        principals.get(identity).cloned()
    }

    /// List all principals.
    pub fn list_principals(&self) -> Vec<Principal> {
        let principals = self.principals.read().unwrap();
        principals.values().cloned().collect()
    }

    /// List all roles.
    pub fn list_roles(&self) -> Vec<Role> {
        let roles = self.roles.read().unwrap();
        roles.values().cloned().collect()
    }

    /// Get the audit log (all entries, in-memory only). For the
    /// persistent audit log, use [`Self::query_audit`].
    pub fn audit_log(&self) -> Vec<AuditEntry> {
        let log = self.audit_log.read().unwrap();
        log.clone()
    }

    /// Get the audit log entries for a workspace (in-memory only).
    /// For the persistent audit log, use [`Self::query_audit`].
    pub fn audit_log_for_workspace(&self, workspace: &str) -> Vec<AuditEntry> {
        let log = self.audit_log.read().unwrap();
        log.iter()
            .filter(|e| e.workspace == workspace)
            .cloned()
            .collect()
    }

    /// Query the persistent audit log (SCALE-05, #184). When a store
    /// is attached, this queries the `workspace_audit` table directly
    /// (the full durable log, not just the in-memory buffer). Without
    /// a store, it falls back to the in-memory log.
    pub fn query_audit(
        &self,
        workspace: Option<&str>,
        since_ms: Option<u64>,
        until_ms: Option<u64>,
        limit: i64,
    ) -> Vec<AuditEntry> {
        if let Some(store) = &self.store {
            match store.query_workspace_audit(
                workspace,
                since_ms.map(|v| v as i64),
                until_ms.map(|v| v as i64),
                limit,
            ) {
                Ok(rows) => rows
                    .into_iter()
                    .map(|r| AuditEntry {
                        seq: r.seq as u64,
                        timestamp_ms: r.timestamp_ms as u64,
                        principal: r.principal,
                        action: r.action,
                        workspace: r.workspace,
                        before: r.before_state,
                        after: r.after_state,
                        request_id: r.request_id,
                    })
                    .collect(),
                Err(err) => {
                    tracing::warn!(
                        code = "workspace_audit_query_failed",
                        "audit query failed ({err}); returning in-memory log"
                    );
                    self.audit_log()
                }
            }
        } else {
            let log = self.audit_log.read().unwrap();
            log.iter()
                .filter(|e| workspace.is_none_or(|ws| e.workspace == ws))
                .filter(|e| since_ms.is_none_or(|s| e.timestamp_ms >= s))
                .filter(|e| until_ms.is_none_or(|u| e.timestamp_ms <= u))
                .take(limit as usize)
                .cloned()
                .collect()
        }
    }

    /// Append an audit entry (assigns the sequence number). When a
    /// store is attached, the entry is also persisted to the
    /// `workspace_audit` table.
    fn append_audit(&self, mut entry: AuditEntry) {
        let mut seq = self.audit_seq.write().unwrap();
        *seq += 1;
        entry.seq = *seq;
        drop(seq);

        // Persist to the durable log.
        if let Some(store) = &self.store {
            if let Err(err) = store.append_workspace_audit(
                entry.timestamp_ms as i64,
                &entry.principal,
                &entry.action,
                &entry.workspace,
                entry.before.as_deref(),
                entry.after.as_deref(),
                &entry.request_id,
            ) {
                tracing::warn!(
                    code = "workspace_audit_persist_failed",
                    "failed to persist audit entry ({err}); in-memory log only"
                );
            }
        }

        let mut log = self.audit_log.write().unwrap();
        log.push(entry);
    }

    /// Record an admin API change in the audit log.
    pub fn record_change(
        &self,
        principal: &str,
        action: &str,
        workspace: &str,
        before: Option<&str>,
        after: Option<&str>,
        request_id: &str,
    ) {
        self.append_audit(AuditEntry {
            seq: 0,
            timestamp_ms: now_unix_ms(),
            principal: principal.to_string(),
            action: action.to_string(),
            workspace: workspace.to_string(),
            before: before.map(String::from),
            after: after.map(String::from),
            request_id: request_id.to_string(),
        });
    }
}

impl Default for WorkspaceManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract the workspace name from a serialized workspace JSON.
fn workspace_name(_: &HashMap<String, Workspace>, json: &str) -> String {
    // Parse the name from the JSON (avoids needing to pass it
    // separately).
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(json) {
        if let Some(name) = v.get("name").and_then(|n| n.as_str()) {
            return name.to_string();
        }
    }
    "unknown".to_string()
}

/// Encode permissions as a JSON array for the store.
fn encode_permissions(perms: &[Permission]) -> String {
    serde_json::to_string(
        &perms
            .iter()
            .map(|p| serde_json::json!({"action": p.action.as_str(), "workspace": &p.workspace}))
            .collect::<Vec<_>>(),
    )
    .unwrap_or_else(|_| "[]".to_string())
}

/// Decode permissions from a JSON array.
fn decode_permissions(json: &str) -> Vec<Permission> {
    let arr: Vec<serde_json::Value> = serde_json::from_str(json).unwrap_or_default();
    arr.into_iter()
        .filter_map(|v| {
            let action_str = v.get("action")?.as_str()?;
            let action = match action_str {
                "read" => Action::Read,
                "write" => Action::Write,
                "admin" => Action::Admin,
                _ => return None,
            };
            let workspace = v.get("workspace")?.as_str()?.to_string();
            Some(Permission { action, workspace })
        })
        .collect()
}

/// Encode role names as a JSON array for the store.
fn encode_role_names(names: &[String]) -> String {
    serde_json::to_string(names).unwrap_or_else(|_| "[]".to_string())
}

/// Decode role names from a JSON array.
fn decode_role_names(json: &str) -> Vec<String> {
    serde_json::from_str(json).unwrap_or_default()
}

/// Wall-clock Unix milliseconds.
fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
