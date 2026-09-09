// Demo Cedar policy set for the Cedar authorization demo (test-21).
//
// Per guide/cedar-authz.md, the gateway's target Cedar integration
// evaluates policies in-process with:
//   - principal = the authenticated consumer   (User::"<name>")
//   - action    = the HTTP method             (read for GET/HEAD/...,
//                write for POST/PUT/PATCH/DELETE)
//   - resource  = the matched route name       (Resource::"<route>")
//
// The target config shape is documented in target-cedar-authz.yaml;
// its config wiring has not landed yet (see README "Documented
// limitations"), so this file is the authored policy that the
// wired-in engine will load. Semantics mirrored live by the demo:
// jwt-user may read (200) but lacks demo:read scope tokens are
// denied (403) on the cedar-route.

permit(
	principal == User::"jwt-user",
	action == Action::"read",
	resource == Resource::"cedar-route"
);

forbid(
	principal == User::"jwt-user",
	action == Action::"delete",
	resource == Resource::"cedar-route"
);
