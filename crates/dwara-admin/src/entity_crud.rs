//! Entity-level CRUD APIs with optimistic concurrency (CFG-02, #181).
//!
//! Per-entity endpoints for routes, services, upstreams, consumers, and
//! policies. Each entity type supports:
//!
//! - `GET /<entity>` — list all entities as JSON.
//! - `GET /<entity>/<name>` — get one entity as JSON (404 if not found).
//! - `POST /<entity>` — create an entity (body = entity JSON). 409 if
//!   the name already exists.
//! - `PUT /<entity>/<name>` — replace an entity (body = entity JSON).
//!   404 if not found.
//! - `DELETE /<entity>/<name>` — delete an entity. 404 if not found.
//!
//! Optimistic concurrency: every GET response carries an `ETag` header
//! (the config content hash). Mutating requests may carry `If-Match`:
//! the gateway compares it to the current ETag and returns 412
//! Precondition Failed on mismatch (the config changed since the
//! client's GET). Without `If-Match`, the mutation applies
//! unconditionally (last-write-wins).
//!
//! All mutations go through the same pipeline as PATCH /config: parse
//! the modified full config, dry-run validate, write atomically,
//! compile-and-publish. The patch_lock serializes concurrent
//! mutations.

use std::sync::Arc;

use http_body_util::{BodyExt, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response};
use serde_json::Value;

use dwara_core::config::{gateway_to_yaml, Consumer, Gateway, Policy, Route, Service, Upstream};

use super::{envelope, generation_headers, json_response, AdminBody, AdminContext};

/// The entity kinds that support CRUD.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntityKind {
    Routes,
    Services,
    Upstreams,
    Consumers,
    Policies,
}

impl EntityKind {
    /// The URL path segment for this entity kind.
    pub fn path(&self) -> &'static str {
        match self {
            EntityKind::Routes => "routes",
            EntityKind::Services => "services",
            EntityKind::Upstreams => "upstreams",
            EntityKind::Consumers => "consumers",
            EntityKind::Policies => "policies",
        }
    }

    /// Parse a path segment into an entity kind.
    pub fn from_path(seg: &str) -> Option<Self> {
        match seg {
            "routes" => Some(EntityKind::Routes),
            "services" => Some(EntityKind::Services),
            "upstreams" => Some(EntityKind::Upstreams),
            "consumers" => Some(EntityKind::Consumers),
            "policies" => Some(EntityKind::Policies),
            _ => None,
        }
    }

    /// Get the entity collection from a Gateway config as a JSON array.
    pub fn list_json(&self, gateway: &Gateway) -> Value {
        match self {
            EntityKind::Routes => {
                serde_json::to_value(&gateway.routes).unwrap_or(Value::Array(vec![]))
            }
            EntityKind::Services => {
                serde_json::to_value(&gateway.services).unwrap_or(Value::Array(vec![]))
            }
            EntityKind::Upstreams => {
                serde_json::to_value(&gateway.upstreams).unwrap_or(Value::Array(vec![]))
            }
            EntityKind::Consumers => {
                serde_json::to_value(&gateway.consumers).unwrap_or(Value::Array(vec![]))
            }
            EntityKind::Policies => {
                serde_json::to_value(&gateway.policies).unwrap_or(Value::Array(vec![]))
            }
        }
    }
}

/// The ETag for the current config: a quoted hex string of the content
/// hash. This is the value clients compare against `If-Match`.
pub fn etag(content_hash: u64) -> String {
    format!("\"{content_hash:#x}\"")
}

/// Check the `If-Match` header against the current ETag. Returns
/// `Ok(())` if the precondition is met (or absent), `Err(())` on
/// mismatch (412 Precondition Failed).
pub fn check_if_match(headers: &hyper::HeaderMap, current_etag: &str) -> Result<(), ()> {
    let Some(if_match) = headers.get(hyper::header::IF_MATCH) else {
        return Ok(());
    };
    let if_match = if_match.to_str().map_err(|_| ())?;
    // Support both `If-Match: "<hash>"` and `If-Match: *` (any).
    if if_match.trim() == "*" {
        return Ok(());
    }
    // Compare loosely (ignore whitespace/quotes).
    let normalized = if_match.trim().trim_matches('"');
    let current = current_etag.trim_matches('"');
    if normalized == current {
        Ok(())
    } else {
        Err(())
    }
}

/// Check if a path matches an entity CRUD route (for fast dispatch
/// without consuming the request). Only matches `/<entity>` or
/// `/<entity>/<name>` (at most 2 segments); deeper paths like
/// `/<entity>/<name>/<sub-resource>` fall through to the existing
/// admin routes.
pub fn is_crud_path(path: &str) -> bool {
    let trimmed = path.trim_start_matches('/');
    let seg = trimmed.split('/').next().unwrap_or("");
    if EntityKind::from_path(seg).is_none() {
        return false;
    }
    // At most 2 segments: <entity> or <entity>/<name>. Deeper paths
    // (e.g. consumers/<name>/credentials) are sub-resources handled
    // by the existing admin routes.
    let seg_count = trimmed.matches('/').count() + 1;
    seg_count <= 2
}

/// Dispatch a CRUD request for an entity kind. Returns `Some(response)`
/// if the request was handled, `None` if the method/path combo is not a
/// valid CRUD operation.
pub async fn try_crud(
    ctx: Arc<AdminContext>,
    req: Request<Incoming>,
    method: &str,
    path: &str,
    request_id: &str,
) -> Option<Response<AdminBody>> {
    // Parse path: /<entity> or /<entity>/<name>.
    let segments: Vec<&str> = path.trim_start_matches('/').splitn(2, '/').collect();
    if segments.is_empty() {
        return None;
    }
    let kind = EntityKind::from_path(segments[0])?;
    let name = segments.get(1).filter(|s| !s.is_empty()).copied();

    match (method, name) {
        ("GET", None) => Some(list_entities(&ctx, kind, request_id).await),
        ("GET", Some(name)) => Some(get_entity(&ctx, kind, name, request_id).await),
        ("POST", None) => Some(create_entity(&ctx, req, kind, request_id).await),
        ("PUT", Some(name)) => Some(replace_entity(&ctx, req, kind, name, request_id).await),
        ("DELETE", Some(name)) => Some(delete_entity(&ctx, req, kind, name, request_id).await),
        _ => None,
    }
}

/// GET /<entity>: list all entities, with ETag.
async fn list_entities(
    ctx: &AdminContext,
    kind: EntityKind,
    _request_id: &str,
) -> Response<AdminBody> {
    let snapshot = ctx.state.snapshot();
    let etag_val = etag(snapshot.content_hash());
    let body = kind.list_json(snapshot.gateway());
    etag_response(json_response(200, body), &etag_val)
}

/// GET /<entity>/<name>: get one entity, with ETag.
async fn get_entity(
    ctx: &AdminContext,
    kind: EntityKind,
    name: &str,
    request_id: &str,
) -> Response<AdminBody> {
    let snapshot = ctx.state.snapshot();
    let etag_val = etag(snapshot.content_hash());
    let entity = find_entity(snapshot.gateway(), kind, name);
    match entity {
        Some(e) => etag_response(json_response(200, e), &etag_val),
        None => envelope(
            404,
            "not_found",
            &format!("{} '{}' not found", kind.path(), name),
            request_id,
        ),
    }
}

/// POST /<entity>: create a new entity. Body = entity JSON. 409 if
/// the name already exists. 412 on If-Match mismatch.
async fn create_entity(
    ctx: &Arc<AdminContext>,
    req: Request<Incoming>,
    kind: EntityKind,
    request_id: &str,
) -> Response<AdminBody> {
    let snapshot = ctx.state.snapshot();
    let current_etag = etag(snapshot.content_hash());
    if let Err(()) = check_if_match(req.headers(), &current_etag) {
        return envelope(
            412,
            "precondition_failed",
            "If-Match does not match the current config ETag",
            request_id,
        );
    }
    let body = match read_body(req, request_id).await {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    let entity_json: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return envelope(
                400,
                "entity_invalid",
                &format!("cannot parse entity JSON: {e}"),
                request_id,
            )
        }
    };
    let name = entity_json
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if name.is_empty() {
        return envelope(
            400,
            "entity_invalid",
            "entity must have a non-empty 'name' field",
            request_id,
        );
    }
    let mut gateway = snapshot.gateway().clone();
    if find_entity(&gateway, kind, &name).is_some() {
        return envelope(
            409,
            "already_exists",
            &format!("{} '{}' already exists", kind.path(), name),
            request_id,
        );
    }
    if let Err(e) = add_entity(&mut gateway, kind, &entity_json) {
        return envelope(400, "entity_invalid", &e, request_id);
    }
    publish_modified(ctx, &gateway, request_id).await
}

/// PUT /<entity>/<name>: replace an entity. 404 if not found. 412 on
/// If-Match mismatch.
async fn replace_entity(
    ctx: &Arc<AdminContext>,
    req: Request<Incoming>,
    kind: EntityKind,
    name: &str,
    request_id: &str,
) -> Response<AdminBody> {
    let snapshot = ctx.state.snapshot();
    let current_etag = etag(snapshot.content_hash());
    if let Err(()) = check_if_match(req.headers(), &current_etag) {
        return envelope(
            412,
            "precondition_failed",
            "If-Match does not match the current config ETag",
            request_id,
        );
    }
    let body = match read_body(req, request_id).await {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    let entity_json: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return envelope(
                400,
                "entity_invalid",
                &format!("cannot parse entity JSON: {e}"),
                request_id,
            )
        }
    };
    let mut gateway = snapshot.gateway().clone();
    if find_entity(&gateway, kind, name).is_none() {
        return envelope(
            404,
            "not_found",
            &format!("{} '{}' not found", kind.path(), name),
            request_id,
        );
    }
    if let Err(e) = replace_entity_in_gateway(&mut gateway, kind, name, &entity_json) {
        return envelope(400, "entity_invalid", &e, request_id);
    }
    publish_modified(ctx, &gateway, request_id).await
}

/// DELETE /<entity>/<name>: delete an entity. 404 if not found. 412 on
/// If-Match mismatch.
async fn delete_entity(
    ctx: &Arc<AdminContext>,
    req: Request<Incoming>,
    kind: EntityKind,
    name: &str,
    request_id: &str,
) -> Response<AdminBody> {
    let snapshot = ctx.state.snapshot();
    let current_etag = etag(snapshot.content_hash());
    if let Err(()) = check_if_match(req.headers(), &current_etag) {
        return envelope(
            412,
            "precondition_failed",
            "If-Match does not match the current config ETag",
            request_id,
        );
    }
    let mut gateway = snapshot.gateway().clone();
    if find_entity(&gateway, kind, name).is_none() {
        return envelope(
            404,
            "not_found",
            &format!("{} '{}' not found", kind.path(), name),
            request_id,
        );
    }
    if let Err(e) = remove_entity(&mut gateway, kind, name) {
        return envelope(400, "entity_invalid", &e, request_id);
    }
    publish_modified(ctx, &gateway, request_id).await
}

/// Find an entity by name in the gateway config. Returns the entity as
/// JSON (Value), or None if not found.
fn find_entity(gateway: &Gateway, kind: EntityKind, name: &str) -> Option<Value> {
    match kind {
        EntityKind::Routes => gateway
            .routes
            .iter()
            .find(|r| r.name == name)
            .and_then(|r| serde_json::to_value(r).ok()),
        EntityKind::Services => gateway
            .services
            .iter()
            .find(|s| s.name == name)
            .and_then(|s| serde_json::to_value(s).ok()),
        EntityKind::Upstreams => gateway
            .upstreams
            .iter()
            .find(|u| u.name == name)
            .and_then(|u| serde_json::to_value(u).ok()),
        EntityKind::Consumers => gateway
            .consumers
            .iter()
            .find(|c| c.name == name)
            .and_then(|c| serde_json::to_value(c).ok()),
        EntityKind::Policies => gateway
            .policies
            .iter()
            .find(|p| p.name == name)
            .and_then(|p| serde_json::to_value(p).ok()),
    }
}

/// Add an entity to the gateway config (append to the collection).
fn add_entity(gateway: &mut Gateway, kind: EntityKind, entity_json: &Value) -> Result<(), String> {
    match kind {
        EntityKind::Routes => {
            let route: Route = serde_json::from_value(entity_json.clone())
                .map_err(|e| format!("cannot deserialize route: {e}"))?;
            gateway.routes.push(route);
        }
        EntityKind::Services => {
            let service: Service = serde_json::from_value(entity_json.clone())
                .map_err(|e| format!("cannot deserialize service: {e}"))?;
            gateway.services.push(service);
        }
        EntityKind::Upstreams => {
            let upstream: Upstream = serde_json::from_value(entity_json.clone())
                .map_err(|e| format!("cannot deserialize upstream: {e}"))?;
            gateway.upstreams.push(upstream);
        }
        EntityKind::Consumers => {
            let consumer: Consumer = serde_json::from_value(entity_json.clone())
                .map_err(|e| format!("cannot deserialize consumer: {e}"))?;
            gateway.consumers.push(consumer);
        }
        EntityKind::Policies => {
            let policy: Policy = serde_json::from_value(entity_json.clone())
                .map_err(|e| format!("cannot deserialize policy: {e}"))?;
            gateway.policies.push(policy);
        }
    }
    Ok(())
}

/// Replace an entity in the gateway config by name.
fn replace_entity_in_gateway(
    gateway: &mut Gateway,
    kind: EntityKind,
    name: &str,
    entity_json: &Value,
) -> Result<(), String> {
    match kind {
        EntityKind::Routes => {
            let route: Route = serde_json::from_value(entity_json.clone())
                .map_err(|e| format!("cannot deserialize route: {e}"))?;
            let idx = gateway
                .routes
                .iter()
                .position(|r| r.name == name)
                .ok_or_else(|| format!("route '{}' not found", name))?;
            gateway.routes[idx] = route;
        }
        EntityKind::Services => {
            let service: Service = serde_json::from_value(entity_json.clone())
                .map_err(|e| format!("cannot deserialize service: {e}"))?;
            let idx = gateway
                .services
                .iter()
                .position(|s| s.name == name)
                .ok_or_else(|| format!("service '{}' not found", name))?;
            gateway.services[idx] = service;
        }
        EntityKind::Upstreams => {
            let upstream: Upstream = serde_json::from_value(entity_json.clone())
                .map_err(|e| format!("cannot deserialize upstream: {e}"))?;
            let idx = gateway
                .upstreams
                .iter()
                .position(|u| u.name == name)
                .ok_or_else(|| format!("upstream '{}' not found", name))?;
            gateway.upstreams[idx] = upstream;
        }
        EntityKind::Consumers => {
            let consumer: Consumer = serde_json::from_value(entity_json.clone())
                .map_err(|e| format!("cannot deserialize consumer: {e}"))?;
            let idx = gateway
                .consumers
                .iter()
                .position(|c| c.name == name)
                .ok_or_else(|| format!("consumer '{}' not found", name))?;
            gateway.consumers[idx] = consumer;
        }
        EntityKind::Policies => {
            let policy: Policy = serde_json::from_value(entity_json.clone())
                .map_err(|e| format!("cannot deserialize policy: {e}"))?;
            let idx = gateway
                .policies
                .iter()
                .position(|p| p.name == name)
                .ok_or_else(|| format!("policy '{}' not found", name))?;
            gateway.policies[idx] = policy;
        }
    }
    Ok(())
}

/// Remove an entity from the gateway config by name.
fn remove_entity(gateway: &mut Gateway, kind: EntityKind, name: &str) -> Result<(), String> {
    match kind {
        EntityKind::Routes => {
            gateway.routes.retain(|r| r.name != name);
        }
        EntityKind::Services => {
            gateway.services.retain(|s| s.name != name);
        }
        EntityKind::Upstreams => {
            gateway.upstreams.retain(|u| u.name != name);
        }
        EntityKind::Consumers => {
            gateway.consumers.retain(|c| c.name != name);
        }
        EntityKind::Policies => {
            gateway.policies.retain(|p| p.name != name);
        }
    }
    Ok(())
}

/// Publish a modified gateway config: validate, write atomically,
/// compile-and-publish. Returns the generation/hash response with
/// ETag. Reuses the same patch_lock as PATCH /config to serialize
/// concurrent mutations.
async fn publish_modified(
    ctx: &Arc<AdminContext>,
    gateway: &Gateway,
    request_id: &str,
) -> Response<AdminBody> {
    // Dry-run validate the modified config.
    if let Err(message) = dry_run(gateway) {
        return envelope(400, "config_invalid", &message, request_id);
    }
    let normalized = match gateway_to_yaml(gateway) {
        Ok(y) => y,
        Err(err) => return envelope(500, "config_serialize_failed", &err.to_string(), request_id),
    };
    let _guard = ctx.patch_lock.lock().await;
    if let Err(err) = write_atomic(&ctx.config_path, &normalized) {
        return envelope(
            500,
            "config_write_failed",
            &format!("failed to write {}: {err}", ctx.config_path.display()),
            request_id,
        );
    }
    match ctx.state.compile_and_publish(gateway) {
        Ok(info) => {
            ctx.dp.refresh();
            tracing::info!(
                code = "admin_entity_crud_published",
                generation = info.generation,
                routes = info.route_count,
                "entity CRUD published config generation {}",
                info.generation
            );
            etag_response(
                generation_headers(
                    json_response(
                        200,
                        serde_json::json!({
                            "generation": info.generation,
                            "content_hash": format!("{:#x}", info.content_hash),
                            "routes": info.route_count,
                        }),
                    ),
                    info.generation,
                    info.content_hash,
                ),
                &etag(info.content_hash),
            )
        }
        Err(err) => envelope(
            500,
            "config_publish_failed",
            &format!("validated config failed to publish: {err}"),
            request_id,
        ),
    }
}

/// Add an ETag header to a response.
fn etag_response(mut resp: Response<AdminBody>, etag_val: &str) -> Response<AdminBody> {
    resp.headers_mut().insert(
        hyper::header::ETAG,
        etag_val.parse().expect("etag header value is valid ASCII"),
    );
    resp
}

/// Read the request body (with a size cap). Returns the body bytes or
/// an error response on failure.
async fn read_body(req: Request<Incoming>, request_id: &str) -> Result<Bytes, Response<AdminBody>> {
    use http_body_util::LengthLimitError;
    const MAX_ENTITY_BODY: usize = 1024 * 1024; // 1 MiB
    let limited = Limited::new(req.into_body(), MAX_ENTITY_BODY);
    match limited.collect().await {
        Ok(c) => Ok(c.to_bytes()),
        Err(err) => {
            if err.downcast_ref::<LengthLimitError>().is_some() {
                Err(envelope(
                    413,
                    "entity_too_large",
                    &format!("entity body exceeds {} bytes", MAX_ENTITY_BODY),
                    request_id,
                ))
            } else {
                Err(envelope(
                    400,
                    "body_read_failed",
                    &err.to_string(),
                    request_id,
                ))
            }
        }
    }
}

// Re-export write_atomic and dry_run from the parent module (they are
// private there; we use them via the `super::` path in the functions
// above). These are NOT re-exports — the functions reference them
// through `super::` which works because this module is a child of the
// admin lib module.

use super::dry_run;
use super::write_atomic;

#[cfg(test)]
mod tests {
    use super::*;
    use dwara_core::config::parse_gateway;

    fn test_gateway() -> Gateway {
        let yaml = "routes:\n  - name: api\n    service: api-svc\n    match:\n      path:\n        type: prefix\n        value: /api\n    action:\n      type: proxy\nservices:\n  - name: api-svc\n    upstream: api-up\nupstreams:\n  - name: api-up\n    endpoints:\n      - address: 127.0.0.1\n        port: 8080\n";
        parse_gateway(yaml).expect("test config parses")
    }

    #[test]
    fn etag_format() {
        assert_eq!(etag(0xdeadbeef), "\"0xdeadbeef\"");
    }

    #[test]
    fn check_if_match_absent() {
        let headers = hyper::HeaderMap::new();
        assert!(check_if_match(&headers, "\"0xabc\"").is_ok());
    }

    #[test]
    fn check_if_match_wildcard() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert(hyper::header::IF_MATCH, "*".parse().unwrap());
        assert!(check_if_match(&headers, "\"0xabc\"").is_ok());
    }

    #[test]
    fn check_if_match_exact() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert(hyper::header::IF_MATCH, "\"0xabc\"".parse().unwrap());
        assert!(check_if_match(&headers, "\"0xabc\"").is_ok());
    }

    #[test]
    fn check_if_match_mismatch() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert(hyper::header::IF_MATCH, "\"0xabc\"".parse().unwrap());
        assert!(check_if_match(&headers, "\"0xdef\"").is_err());
    }

    #[test]
    fn entity_kind_from_path() {
        assert_eq!(EntityKind::from_path("routes"), Some(EntityKind::Routes));
        assert_eq!(
            EntityKind::from_path("services"),
            Some(EntityKind::Services)
        );
        assert_eq!(
            EntityKind::from_path("upstreams"),
            Some(EntityKind::Upstreams)
        );
        assert_eq!(
            EntityKind::from_path("consumers"),
            Some(EntityKind::Consumers)
        );
        assert_eq!(
            EntityKind::from_path("policies"),
            Some(EntityKind::Policies)
        );
        assert_eq!(EntityKind::from_path("unknown"), None);
    }

    #[test]
    fn find_entity_route() {
        let gw = test_gateway();
        let found = find_entity(&gw, EntityKind::Routes, "api");
        assert!(found.is_some());
        assert_eq!(found.unwrap()["name"], "api");
    }

    #[test]
    fn find_entity_not_found() {
        let gw = test_gateway();
        assert!(find_entity(&gw, EntityKind::Routes, "missing").is_none());
    }

    #[test]
    fn remove_entity_route() {
        let mut gw = test_gateway();
        assert!(remove_entity(&mut gw, EntityKind::Routes, "api").is_ok());
        assert!(gw.routes.is_empty());
    }

    #[test]
    fn list_entities_json() {
        let gw = test_gateway();
        let json = EntityKind::Routes.list_json(&gw);
        assert!(json.is_array());
        assert_eq!(json.as_array().unwrap().len(), 1);
    }

    #[test]
    fn add_and_remove_route() {
        let mut gw = test_gateway();
        let route_json = serde_json::json!({
            "name": "new-route",
            "service": "api-svc",
            "match": {"path": {"type": "prefix", "value": "/new"}},
            "action": {"type": "proxy"}
        });
        assert!(add_entity(&mut gw, EntityKind::Routes, &route_json).is_ok());
        assert_eq!(gw.routes.len(), 2);
        assert!(remove_entity(&mut gw, EntityKind::Routes, "new-route").is_ok());
        assert_eq!(gw.routes.len(), 1);
    }

    #[test]
    fn replace_route() {
        let mut gw = test_gateway();
        let route_json = serde_json::json!({
            "name": "api",
            "service": "api-svc",
            "match": {"path": {"type": "exact", "value": "/api/v2"}},
            "action": {"type": "proxy"}
        });
        assert!(replace_entity_in_gateway(&mut gw, EntityKind::Routes, "api", &route_json).is_ok());
        assert_eq!(gw.routes[0].r#match.path.value, "/api/v2");
    }
}
