//! Unit tests for `workspace` (relocated from src).

#![cfg(feature = "ent")]

use dwara_core::workspace::{Action, Permission, Role, Workspace, WorkspaceManager};

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
