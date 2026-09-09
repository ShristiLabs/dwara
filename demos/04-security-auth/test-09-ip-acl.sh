#!/bin/bash
# test-09-ip-acl.sh — IP access control list.
#
# The ip-acl-route has an IP ACL that allows private/loopback ranges
# (127.0.0.1, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) with a default
# deny. Requests from localhost (127.0.0.1) should be allowed (200).
set -euo pipefail
source ../_shared/helpers.sh

echo "=== test-09-ip-acl ==="

# Wait for the gateway to be ready.
wait_for http://localhost:8080/public/ 30 || exit 1

# Request from localhost (127.0.0.1) -> 200 (allowed by IP ACL).
status=$(http_status http://localhost:8080/v1/acl/test)
assert_status 200 "$status" "localhost request allowed by IP ACL (200)"

print_summary
