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
//! ## Feature gate
//!
//! The `enterprise` cargo feature must be enabled. Without it, the
//! module is not compiled and the gateway runs in single-workspace
//! mode (the default OSS behavior).

use std::collections::HashMap;
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

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
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Permission {
    /// The action: "read", "write", or "admin".
    pub action: Action,
    /// The resource: a workspace name, or "*" for all workspaces.
    pub workspace: String,
}

/// The action a permission grants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
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
        match (self, other) {
            (Action::Admin, _) => true,
            (Action::Write, Action::Write) | (Action::Write, Action::Read) => true,
            (Action::Read, Action::Read) => true,
            _ => false,
        }
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
/// the audit log.
pub struct WorkspaceManager {
    workspaces: RwLock<HashMap<String, Workspace>>,
    roles: RwLock<HashMap<String, Role>>,
    principals: RwLock<HashMap<String, Principal>>,
    audit_log: RwLock<Vec<AuditEntry>>,
    audit_seq: RwLock<u64>,
}

impl WorkspaceManager {
    /// Create a new workspace manager with a single default workspace
    /// (the OSS behavior).
    pub fn new() -> Self {
        let mut workspaces = HashMap::new();
        workspaces.insert(
            "default".to_string(),
            Workspace {
                name: "default".to_string(),
                description: "Default workspace".to_string(),
                active: true,
            },
        );
        Self {
            workspaces: RwLock::new(workspaces),
            roles: RwLock::new(HashMap::new()),
            principals: RwLock::new(HashMap::new()),
            audit_log: RwLock::new(Vec::new()),
            audit_seq: RwLock::new(0),
        }
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
        roles.insert(role.name.clone(), role);
        Ok(())
    }

    /// Get a principal.
    pub fn get_principal(&self, identity: &str) -> Option<Principal> {
        let principals = self.principals.read().unwrap();
        principals.get(identity).cloned()
    }

    /// Get the audit log (all entries).
    pub fn audit_log(&self) -> Vec<AuditEntry> {
        let log = self.audit_log.read().unwrap();
        log.clone()
    }

    /// Get the audit log entries for a workspace.
    pub fn audit_log_for_workspace(&self, workspace: &str) -> Vec<AuditEntry> {
        let log = self.audit_log.read().unwrap();
        log.iter()
            .filter(|e| e.workspace == workspace)
            .cloned()
            .collect()
    }

    /// Append an audit entry (assigns the sequence number).
    fn append_audit(&self, mut entry: AuditEntry) {
        let mut seq = self.audit_seq.write().unwrap();
        *seq += 1;
        entry.seq = *seq;
        drop(seq);

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

/// Wall-clock Unix milliseconds.
fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admin_role() -> Role {
        Role {
            name: "admin".to_string(),
            permissions: vec![Permission {
                action: Action::Admin,
                workspace: "*".to_string(),
            }],
        }
    }

    fn reader_role() -> Role {
        Role {
            name: "reader".to_string(),
            permissions: vec![Permission {
                action: Action::Read,
                workspace: "*".to_string(),
            }],
        }
    }

    fn writer_role_for(ws: &str) -> Role {
        Role {
            name: format!("{ws}-writer"),
            permissions: vec![Permission {
                action: Action::Write,
                workspace: ws.to_string(),
            }],
        }
    }

    #[test]
    fn default_workspace_exists() {
        let mgr = WorkspaceManager::new();
        let ws = mgr.get_workspace("default").unwrap();
        assert_eq!(ws.name, "default");
        assert!(ws.active);
    }

    #[test]
    fn create_workspace_requires_admin() {
        let mgr = WorkspaceManager::new();
        let ws = Workspace {
            name: "tenant-a".to_string(),
            description: "Tenant A".to_string(),
            active: true,
        };
        // No principal -> denied.
        let err = mgr
            .create_workspace("unknown", ws.clone(), "req-1")
            .unwrap_err();
        assert!(err.contains("permission denied"));
    }

    #[test]
    fn create_workspace_with_admin_succeeds() {
        let mgr = WorkspaceManager::new();
        mgr.add_role(admin_role()).unwrap();
        mgr.assign_role("admin-cert", "admin", "req-0").unwrap();

        let ws = Workspace {
            name: "tenant-a".to_string(),
            description: "Tenant A".to_string(),
            active: true,
        };
        mgr.create_workspace("admin-cert", ws, "req-1").unwrap();
        assert!(mgr.get_workspace("tenant-a").is_some());
    }

    #[test]
    fn cannot_create_duplicate_workspace() {
        let mgr = WorkspaceManager::new();
        mgr.add_role(admin_role()).unwrap();
        mgr.assign_role("admin-cert", "admin", "req-0").unwrap();

        let ws = Workspace {
            name: "tenant-a".to_string(),
            description: "Tenant A".to_string(),
            active: true,
        };
        mgr.create_workspace("admin-cert", ws.clone(), "req-1")
            .unwrap();
        let err = mgr.create_workspace("admin-cert", ws, "req-2").unwrap_err();
        assert!(err.contains("already exists"));
    }

    #[test]
    fn cannot_delete_default_workspace() {
        let mgr = WorkspaceManager::new();
        mgr.add_role(admin_role()).unwrap();
        mgr.assign_role("admin-cert", "admin", "req-0").unwrap();

        let err = mgr
            .delete_workspace("admin-cert", "default", "req-1")
            .unwrap_err();
        assert!(err.contains("cannot delete the default"));
    }

    #[test]
    fn delete_workspace_succeeds() {
        let mgr = WorkspaceManager::new();
        mgr.add_role(admin_role()).unwrap();
        mgr.assign_role("admin-cert", "admin", "req-0").unwrap();

        let ws = Workspace {
            name: "tenant-a".to_string(),
            description: "Tenant A".to_string(),
            active: true,
        };
        mgr.create_workspace("admin-cert", ws, "req-1").unwrap();
        mgr.delete_workspace("admin-cert", "tenant-a", "req-2")
            .unwrap();
        assert!(mgr.get_workspace("tenant-a").is_none());
    }

    #[test]
    fn reader_cannot_write() {
        let mgr = WorkspaceManager::new();
        mgr.add_role(reader_role()).unwrap();
        mgr.assign_role("reader-cert", "reader", "req-0").unwrap();

        assert!(mgr.check_permission("reader-cert", Action::Read, "default"));
        assert!(!mgr.check_permission("reader-cert", Action::Write, "default"));
        assert!(!mgr.check_permission("reader-cert", Action::Admin, "default"));
    }

    #[test]
    fn writer_can_write_only_in_workspace() {
        let mgr = WorkspaceManager::new();
        mgr.add_role(writer_role_for("tenant-a")).unwrap();
        mgr.assign_role("writer-cert", "tenant-a-writer", "req-0")
            .unwrap();

        assert!(mgr.check_permission("writer-cert", Action::Write, "tenant-a"));
        assert!(mgr.check_permission("writer-cert", Action::Read, "tenant-a"));
        assert!(!mgr.check_permission("writer-cert", Action::Write, "tenant-b"));
        assert!(!mgr.check_permission("writer-cert", Action::Admin, "tenant-a"));
    }

    #[test]
    fn admin_implies_all() {
        assert!(Action::Admin.implies(Action::Read));
        assert!(Action::Admin.implies(Action::Write));
        assert!(Action::Admin.implies(Action::Admin));
        assert!(Action::Write.implies(Action::Read));
        assert!(!Action::Write.implies(Action::Admin));
        assert!(Action::Read.implies(Action::Read));
        assert!(!Action::Read.implies(Action::Write));
    }

    #[test]
    fn cross_workspace_access_denied() {
        let mgr = WorkspaceManager::new();
        mgr.add_role(writer_role_for("tenant-a")).unwrap();
        mgr.assign_role("writer-cert", "tenant-a-writer", "req-0")
            .unwrap();

        // Writer for tenant-a cannot access tenant-b.
        assert!(!mgr.check_permission("writer-cert", Action::Write, "tenant-b"));
        assert!(!mgr.check_permission("writer-cert", Action::Read, "tenant-b"));
    }

    #[test]
    fn audit_log_records_changes() {
        let mgr = WorkspaceManager::new();
        mgr.add_role(admin_role()).unwrap();
        mgr.assign_role("admin-cert", "admin", "req-0").unwrap();

        let ws = Workspace {
            name: "tenant-a".to_string(),
            description: "Tenant A".to_string(),
            active: true,
        };
        mgr.create_workspace("admin-cert", ws, "req-1").unwrap();
        mgr.delete_workspace("admin-cert", "tenant-a", "req-2")
            .unwrap();

        let log = mgr.audit_log();
        assert_eq!(log.len(), 3); // assign_role + create + delete
        assert_eq!(log[0].action, "role.assign");
        assert_eq!(log[1].action, "workspace.create");
        assert_eq!(log[2].action, "workspace.delete");
        assert_eq!(log[1].principal, "admin-cert");
        assert!(log[1].after.is_some());
        assert!(log[2].before.is_some());
        assert!(log[2].after.is_none());
    }

    #[test]
    fn audit_log_is_sequential() {
        let mgr = WorkspaceManager::new();
        mgr.record_change("admin", "test.action", "default", None, None, "req-1");
        mgr.record_change("admin", "test.action", "default", None, None, "req-2");
        mgr.record_change("admin", "test.action", "default", None, None, "req-3");

        let log = mgr.audit_log();
        assert_eq!(log.len(), 3);
        assert_eq!(log[0].seq, 1);
        assert_eq!(log[1].seq, 2);
        assert_eq!(log[2].seq, 3);
    }

    #[test]
    fn audit_log_for_workspace_filters() {
        let mgr = WorkspaceManager::new();
        mgr.record_change("admin", "action1", "tenant-a", None, None, "req-1");
        mgr.record_change("admin", "action2", "tenant-b", None, None, "req-2");
        mgr.record_change("admin", "action3", "tenant-a", None, None, "req-3");

        let log = mgr.audit_log_for_workspace("tenant-a");
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].action, "action1");
        assert_eq!(log[1].action, "action3");
    }

    #[test]
    fn unknown_principal_denied() {
        let mgr = WorkspaceManager::new();
        assert!(!mgr.check_permission("unknown", Action::Read, "default"));
        assert!(!mgr.check_permission("unknown", Action::Write, "default"));
    }

    #[test]
    fn list_workspaces() {
        let mgr = WorkspaceManager::new();
        mgr.add_role(admin_role()).unwrap();
        mgr.assign_role("admin-cert", "admin", "req-0").unwrap();

        mgr.create_workspace(
            "admin-cert",
            Workspace {
                name: "tenant-a".to_string(),
                description: "Tenant A".to_string(),
                active: true,
            },
            "req-1",
        )
        .unwrap();

        let list = mgr.list_workspaces();
        assert_eq!(list.len(), 2); // default + tenant-a
        assert!(list.iter().any(|w| w.name == "default"));
        assert!(list.iter().any(|w| w.name == "tenant-a"));
    }

    #[test]
    fn assign_role_idempotent() {
        let mgr = WorkspaceManager::new();
        mgr.add_role(admin_role()).unwrap();
        mgr.assign_role("admin-cert", "admin", "req-0").unwrap();
        mgr.assign_role("admin-cert", "admin", "req-1").unwrap();

        let principal = mgr.get_principal("admin-cert").unwrap();
        assert_eq!(principal.roles.len(), 1); // Not duplicated.
    }

    #[test]
    fn add_duplicate_role_fails() {
        let mgr = WorkspaceManager::new();
        mgr.add_role(admin_role()).unwrap();
        let err = mgr.add_role(admin_role()).unwrap_err();
        assert!(err.contains("already exists"));
    }

    #[test]
    fn assign_nonexistent_role_fails() {
        let mgr = WorkspaceManager::new();
        let err = mgr.assign_role("cert", "nonexistent", "req-0").unwrap_err();
        assert!(err.contains("not found"));
    }
}
