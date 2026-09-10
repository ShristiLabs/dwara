//! Workspace admin API endpoints (SCALE-05, #184, ent only).
//!
//! Endpoints for workspace CRUD, RBAC role management, principal role
//! assignment, and audit log queries. All mutations are persisted to
//! the state store when one is attached; without a store they run
//! in-memory only.
//!
//! # Endpoints
//!
//! - `GET /workspaces` — list all workspaces.
//! - `GET /workspaces/:name` — get one workspace (404 if not found).
//! - `POST /workspaces` — create a workspace (body = workspace JSON).
//!   409 if the name already exists.
//! - `DELETE /workspaces/:name` — delete a workspace (404 if not
//!   found, 400 for the default workspace).
//! - `GET /roles` — list all RBAC roles.
//! - `POST /roles` — create a role (body = role JSON). 409 if the
//!   name already exists.
//! - `GET /principals` — list all principals.
//! - `GET /principals/:identity` — get one principal (404 if not
//!   found).
//! - `POST /principals/:identity/roles` — assign a role to a
//!   principal (body = `{"role": "<name>"}`). 404 if the role is not
//!   found.
//! - `GET /audit` — query the audit log. Query params: `workspace`,
//!   `since_ms`, `until_ms`, `limit` (default 100).

use std::sync::Arc;

#[cfg(feature = "ent")]
use http_body_util::{BodyExt as _, Limited};
#[cfg(feature = "ent")]
use hyper::body::Incoming;
use hyper::{Request, Response};

#[cfg(feature = "ent")]
use super::{envelope, json_response};
use super::{AdminBody, AdminContext};

/// Hard cap on workspace/role/principal bodies (small JSON).
#[cfg(feature = "ent")]
const MAX_BODY: usize = 64 * 1024;

/// Default audit query limit.
#[cfg(feature = "ent")]
const DEFAULT_AUDIT_LIMIT: i64 = 100;

/// Maximum audit query limit.
#[cfg(feature = "ent")]
const MAX_AUDIT_LIMIT: i64 = 10_000;

/// Check whether a path starts with a workspace admin route prefix.
pub fn is_workspace_path(path: &str) -> bool {
    path == "/workspaces"
        || path.starts_with("/workspaces/")
        || path == "/roles"
        || path == "/principals"
        || path.starts_with("/principals/")
        || path == "/audit"
}

/// Try to handle a workspace admin request. Returns `Some(response)`
/// when the path matches a workspace route, `None` otherwise (fall
/// through to the existing routes).
#[cfg(feature = "ent")]
pub async fn try_workspace(
    ctx: Arc<AdminContext>,
    req: Request<Incoming>,
    method: &str,
    path: &str,
    request_id: &str,
) -> Option<Response<AdminBody>> {
    let ws = ctx.workspace.clone()?;
    let resp = handle(&ctx, &ws, req, method, path, request_id).await;
    Some(resp)
}

/// Non-ent stub: workspace endpoints are not available without the
/// `ent` cargo feature. Always returns `None` (fall through).
#[cfg(not(feature = "ent"))]
pub async fn try_workspace(
    _ctx: Arc<AdminContext>,
    _req: Request<hyper::body::Incoming>,
    _method: &str,
    _path: &str,
    _request_id: &str,
) -> Option<Response<AdminBody>> {
    None
}

#[cfg(feature = "ent")]
async fn handle(
    _ctx: &AdminContext,
    ws: &Arc<dwara_core::workspace::WorkspaceManager>,
    req: Request<Incoming>,
    method: &str,
    path: &str,
    request_id: &str,
) -> Response<AdminBody> {
    use dwara_core::workspace::{Action, Permission, Role, Workspace};

    // --- Workspaces ---
    if path == "/workspaces" && method == "GET" {
        let list = ws.list_workspaces();
        return json_response(200, serde_json::to_value(&list).unwrap_or_default());
    }
    if path == "/workspaces" && method == "POST" {
        let limited = Limited::new(req.into_body(), MAX_BODY);
        let body = match limited.collect().await {
            Ok(c) => c.to_bytes(),
            Err(_) => {
                return envelope(400, "body_read_failed", "failed to read body", request_id);
            }
        };
        let workspace: Workspace = match serde_json::from_slice(&body) {
            Ok(w) => w,
            Err(err) => {
                return envelope(400, "invalid_workspace", &err.to_string(), request_id);
            }
        };
        // The acting principal: in production this comes from the mTLS
        // client certificate. For now we use a placeholder (the admin
        // surface is mTLS-gated, so the principal is authenticated).
        let principal = "admin";
        return match ws.create_workspace(principal, workspace, request_id) {
            Ok(()) => {
                let list = ws.list_workspaces();
                json_response(201, serde_json::to_value(&list).unwrap_or_default())
            }
            Err(err) => {
                let status = if err.contains("already exists") {
                    409
                } else {
                    403
                };
                envelope(status, "workspace_create_failed", &err, request_id)
            }
        };
    }
    if let Some(name) = path.strip_prefix("/workspaces/") {
        if method == "GET" {
            return match ws.get_workspace(name) {
                Some(w) => json_response(200, serde_json::to_value(&w).unwrap_or_default()),
                None => envelope(404, "not_found", "workspace not found", request_id),
            };
        }
        if method == "DELETE" {
            let principal = "admin";
            return match ws.delete_workspace(principal, name, request_id) {
                Ok(()) => {
                    let list = ws.list_workspaces();
                    json_response(200, serde_json::to_value(&list).unwrap_or_default())
                }
                Err(err) => {
                    let status = if err.contains("not found") {
                        404
                    } else if err.contains("cannot delete") {
                        400
                    } else {
                        403
                    };
                    envelope(status, "workspace_delete_failed", &err, request_id)
                }
            };
        }
    }

    // --- Roles ---
    if path == "/roles" && method == "GET" {
        let roles = ws.list_roles();
        return json_response(
            200,
            serde_json::to_value(
                roles
                    .iter()
                    .map(|r| {
                        serde_json::json!({
                            "name": &r.name,
                            "permissions": r.permissions.iter().map(|p| {
                                serde_json::json!({
                                    "action": p.action.as_str(),
                                    "workspace": &p.workspace,
                                })
                            }).collect::<Vec<_>>(),
                        })
                    })
                    .collect::<Vec<_>>(),
            )
            .unwrap_or_default(),
        );
    }
    if path == "/roles" && method == "POST" {
        let limited = Limited::new(req.into_body(), MAX_BODY);
        let body = match limited.collect().await {
            Ok(c) => c.to_bytes(),
            Err(_) => {
                return envelope(400, "body_read_failed", "failed to read body", request_id);
            }
        };
        let val: serde_json::Value = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(err) => {
                return envelope(400, "invalid_role", &err.to_string(), request_id);
            }
        };
        let name = match val.get("name").and_then(|v| v.as_str()) {
            Some(n) => n.to_string(),
            None => {
                return envelope(400, "invalid_role", "missing 'name' field", request_id);
            }
        };
        let perms = match val.get("permissions").and_then(|v| v.as_array()) {
            Some(arr) => arr
                .iter()
                .filter_map(|p| {
                    let action_str = p.get("action")?.as_str()?;
                    let action = match action_str {
                        "read" => Action::Read,
                        "write" => Action::Write,
                        "admin" => Action::Admin,
                        _ => return None,
                    };
                    let workspace = p.get("workspace")?.as_str()?.to_string();
                    Some(Permission { action, workspace })
                })
                .collect::<Vec<_>>(),
            None => Vec::new(),
        };
        return match ws.add_role(Role {
            name: name.clone(),
            permissions: perms,
        }) {
            Ok(()) => {
                let roles = ws.list_roles();
                json_response(
                    201,
                    serde_json::to_value(
                        roles
                            .iter()
                            .map(|r| {
                                serde_json::json!({
                                    "name": &r.name,
                                    "permissions": r.permissions.iter().map(|p| {
                                        serde_json::json!({
                                            "action": p.action.as_str(),
                                            "workspace": &p.workspace,
                                        })
                                    }).collect::<Vec<_>>(),
                                })
                            })
                            .collect::<Vec<_>>(),
                    )
                    .unwrap_or_default(),
                )
            }
            Err(err) => {
                let status = if err.contains("already exists") {
                    409
                } else {
                    400
                };
                envelope(status, "role_create_failed", &err, request_id)
            }
        };
    }

    // --- Principals ---
    if path == "/principals" && method == "GET" {
        let principals = ws.list_principals();
        return json_response(
            200,
            serde_json::to_value(
                principals
                    .iter()
                    .map(|p| serde_json::json!({"identity": &p.identity, "roles": &p.roles}))
                    .collect::<Vec<_>>(),
            )
            .unwrap_or_default(),
        );
    }
    if let Some(identity) = path.strip_prefix("/principals/") {
        if method == "GET" && !identity.contains('/') {
            return match ws.get_principal(identity) {
                Some(p) => json_response(
                    200,
                    serde_json::json!({"identity": &p.identity, "roles": &p.roles}),
                ),
                None => envelope(404, "not_found", "principal not found", request_id),
            };
        }
        // Handle /principals/:identity/roles
        if let Some(id) = identity.strip_suffix("/roles") {
            if method == "POST" {
                let limited = Limited::new(req.into_body(), MAX_BODY);
                let body = match limited.collect().await {
                    Ok(c) => c.to_bytes(),
                    Err(_) => {
                        return envelope(
                            400,
                            "body_read_failed",
                            "failed to read body",
                            request_id,
                        );
                    }
                };
                let val: serde_json::Value = match serde_json::from_slice(&body) {
                    Ok(v) => v,
                    Err(err) => {
                        return envelope(400, "invalid_body", &err.to_string(), request_id);
                    }
                };
                let role_name = match val.get("role").and_then(|v| v.as_str()) {
                    Some(r) => r.to_string(),
                    None => {
                        return envelope(400, "invalid_body", "missing 'role' field", request_id);
                    }
                };
                return match ws.assign_role(id, &role_name, request_id) {
                    Ok(()) => {
                        let p = ws.get_principal(id);
                        json_response(
                            200,
                            serde_json::json!({"identity": id, "roles": p.map(|x| x.roles).unwrap_or_default()}),
                        )
                    }
                    Err(err) => {
                        let status = if err.contains("not found") { 404 } else { 400 };
                        envelope(status, "role_assign_failed", &err, request_id)
                    }
                };
            }
        }
    }

    // --- Audit ---
    if path == "/audit" && method == "GET" {
        let query = req.uri().query().unwrap_or("");
        let mut workspace: Option<String> = None;
        let mut since_ms: Option<u64> = None;
        let mut until_ms: Option<u64> = None;
        let mut limit = DEFAULT_AUDIT_LIMIT;
        for kv in query.split('&') {
            if let Some(val) = kv.strip_prefix("workspace=") {
                workspace = Some(val.to_string());
            } else if let Some(val) = kv.strip_prefix("since_ms=") {
                since_ms = val.parse().ok();
            } else if let Some(val) = kv.strip_prefix("until_ms=") {
                until_ms = val.parse().ok();
            } else if let Some(val) = kv.strip_prefix("limit=") {
                if let Ok(l) = val.parse::<i64>() {
                    limit = l.clamp(1, MAX_AUDIT_LIMIT);
                }
            }
        }
        let entries = ws.query_audit(workspace.as_deref(), since_ms, until_ms, limit);
        return json_response(
            200,
            serde_json::to_value(
                entries
                    .iter()
                    .map(|e| {
                        serde_json::json!({
                            "seq": e.seq,
                            "timestamp_ms": e.timestamp_ms,
                            "principal": &e.principal,
                            "action": &e.action,
                            "workspace": &e.workspace,
                            "before": &e.before,
                            "after": &e.after,
                            "request_id": &e.request_id,
                        })
                    })
                    .collect::<Vec<_>>(),
            )
            .unwrap_or_default(),
        );
    }

    envelope(404, "not_found", "unknown workspace admin path", request_id)
}
