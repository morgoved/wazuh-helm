#!/usr/bin/env bash
# Render tests for the dashboard Gateway API resources (HTTPRoute / ListenerSet /
# BackendTLSPolicy / Certificate) and for the config templating fix (#173).
#
# Usage: charts/wazuh/tests/render_test.sh
# Requires: helm on PATH. No cluster access needed (pure `helm template`).
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHART_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RELEASE=test

pass=0
fail=0

render() {
  helm template "$RELEASE" "$CHART_DIR" "$@"
}

expect_failure() {
  local name="$1"; shift
  if render "$@" >/dev/null 2>/tmp/wazuh-render-test.err; then
    echo "FAIL: $name (expected helm template to fail, it succeeded)"
    fail=$((fail + 1))
  else
    echo "PASS: $name"
    pass=$((pass + 1))
  fi
}

assert_contains() {
  local name="$1" haystack="$2" needle="$3"
  if grep -qF -- "$needle" <<<"$haystack"; then
    echo "PASS: $name"
    pass=$((pass + 1))
  else
    echo "FAIL: $name (expected to find: $needle)"
    fail=$((fail + 1))
  fi
}

assert_not_contains() {
  local name="$1" haystack="$2" needle="$3"
  if grep -qF -- "$needle" <<<"$haystack"; then
    echo "FAIL: $name (did not expect to find: $needle)"
    fail=$((fail + 1))
  else
    echo "PASS: $name"
    pass=$((pass + 1))
  fi
}

echo "== Gateway disabled (default): no Gateway API resource is rendered =="
out=$(render)
assert_not_contains "no BackendTLSPolicy by default" "$out" "kind: BackendTLSPolicy"
assert_not_contains "no ListenerSet by default" "$out" "kind: ListenerSet"
assert_not_contains "no HTTPRoute by default" "$out" "kind: HTTPRoute"

echo "== Gateway enabled without parentRef.name must fail fast =="
expect_failure "missing parentRef.name" --set dashboard.gateway.enabled=true

echo "== HTTP backend, attached via a chart-managed ListenerSet =="
out=$(render --set dashboard.gateway.enabled=true --set dashboard.gateway.parentRef.name=my-gw)
assert_contains "ListenerSet rendered" "$out" "kind: ListenerSet"
assert_contains "listener protocol is HTTP" "$out" "protocol: HTTP"
assert_contains "HTTPRoute attaches to the ListenerSet" "$out" "kind: ListenerSet"

echo "== HTTPS backend (dashboard.enable_ssl) requires backendTLS.caCertificateRef.name =="
expect_failure "missing backendTLS.caCertificateRef.name" \
  --set dashboard.gateway.enabled=true --set dashboard.gateway.parentRef.name=my-gw --set dashboard.enable_ssl=true

out=$(render --set dashboard.gateway.enabled=true --set dashboard.gateway.parentRef.name=my-gw \
  --set dashboard.enable_ssl=true --set dashboard.gateway.backendTLS.caCertificateRef.name=dashboard-ca-bundle)
assert_contains "BackendTLSPolicy rendered" "$out" "kind: BackendTLSPolicy"
assert_contains "BackendTLSPolicy CA ref is a ConfigMap" "$out" "kind: ConfigMap"
assert_contains "BackendTLSPolicy CA ref name is passed through" "$out" "name: dashboard-ca-bundle"
assert_contains "BackendTLSPolicy hostname matches the dashboard certificate SAN" "$out" "hostname: test-wazuh-dashboard"

echo "== Edge TLS: a generated Certificate requires tls.issuerRef.name =="
expect_failure "missing tls.issuerRef.name" \
  --set dashboard.gateway.enabled=true --set dashboard.gateway.parentRef.name=my-gw --set dashboard.gateway.tls.enabled=true

out=$(render --set dashboard.gateway.enabled=true --set dashboard.gateway.parentRef.name=my-gw \
  --set dashboard.gateway.tls.enabled=true --set dashboard.gateway.tls.issuerRef.name=my-issuer)
assert_contains "gateway edge Certificate is rendered" "$out" "name: test-wazuh-dashboard-letsencrypt"
assert_contains "listener uses HTTPS" "$out" "protocol: HTTPS"

echo "== Edge TLS: an existing Secret skips Certificate creation =="
out=$(render --set dashboard.gateway.enabled=true --set dashboard.gateway.parentRef.name=my-gw \
  --set dashboard.gateway.tls.enabled=true --set dashboard.gateway.tls.certificate.create=false \
  --set dashboard.gateway.tls.secretName=my-existing-secret)
assert_contains "listener references the existing secret" "$out" "name: my-existing-secret"
assert_not_contains "no Certificate is generated" "$out" "test-wazuh-dashboard-letsencrypt"

echo "== Direct Gateway attachment (dashboard.gateway.listenerSet.enabled=false) =="
out=$(render --set dashboard.gateway.enabled=true --set dashboard.gateway.parentRef.name=my-gw \
  --set dashboard.gateway.listenerSet.enabled=false)
assert_not_contains "no ListenerSet is rendered" "$out" "kind: ListenerSet"
assert_contains "HTTPRoute is rendered" "$out" "kind: HTTPRoute"
assert_contains "HTTPRoute parentRef targets the Gateway directly" "$out" "kind: Gateway"

echo "== Ingress and Gateway can coexist =="
out=$(render --set dashboard.ingress.enabled=true --set dashboard.gateway.enabled=true --set dashboard.gateway.parentRef.name=my-gw)
assert_contains "Ingress is still rendered" "$out" "kind: Ingress"
assert_contains "HTTPRoute is rendered alongside the Ingress" "$out" "kind: HTTPRoute"

echo "== #173: single-quoted include() inside a templated config block renders through tpl =="
cat >/tmp/wazuh-render-test-173-values.yaml <<'EOF'
indexer:
  config:
    internalUsers: |-
      ---
      _meta:
        type: "internalusers"
        config_version: 2

      admin:
        hash: '{{ include "wazuh.indexer.passwordHash" . }}'
        reserved: true
        backend_roles:
          - "admin"
        description: "Admin user"
EOF
out=$(render -f /tmp/wazuh-render-test-173-values.yaml)
assert_contains "internalUsers.hash is templated to the actual password hash" "$out" \
  "hash: '\$2a\$12\$zGWIT7wkPKT/zww3bmMyp.KuWXH4RzgxiB91Q8NGFcqpyPy.R2Rcq'"
rm -f /tmp/wazuh-render-test-173-values.yaml

echo
echo "==================================="
echo "PASS: $pass  FAIL: $fail"
[ "$fail" -eq 0 ]
