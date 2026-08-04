#!/usr/bin/env bash
# Render tests for the dashboard Gateway API resources (HTTPRoute / ListenerSet /
# BackendTLSPolicy / Certificate) and for the config templating fix (#173).
#
# Usage: charts/wazuh/tests/render_test.sh
# Requires: helm on PATH. No cluster access needed (pure `helm template`).
# Fetches the chart's dependencies (cert-manager) on every run, so it works
# from a clean checkout without a manual `helm dependency build` step.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHART_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RELEASE=test

helm dependency build "$CHART_DIR" >/dev/null

pass=0
fail=0

render() {
  helm template "$RELEASE" "$CHART_DIR" "$@"
}

# render_only <template-path> [helm template args...]
# Renders a single template's manifest, so assertions can't accidentally
# match an unrelated resource elsewhere in the chart's output.
render_only() {
  local tmpl="$1"; shift
  render --show-only "$tmpl" "$@"
}

expect_success() {
  local name="$1"; shift
  if "$@" >/dev/null 2>/tmp/wazuh-render-test.err; then
    echo "PASS: $name"
    pass=$((pass + 1))
  else
    echo "FAIL: $name (expected helm template to succeed)"
    cat /tmp/wazuh-render-test.err
    fail=$((fail + 1))
  fi
}

expect_failure() {
  local name="$1"; shift
  if "$@" >/dev/null 2>/tmp/wazuh-render-test.err; then
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

LISTENERSET=templates/dashboard/listenerset.yaml
HTTPROUTE=templates/dashboard/httproute.yaml
BACKENDTLSPOLICY=templates/dashboard/backendtlspolicy.yaml
GATEWAY_CERTIFICATE=templates/dashboard/certificate.yaml
INGRESS=templates/dashboard/ingress.yaml
INDEXER_SECURITYCONFIG=templates/indexer/secret-securityconfig.yaml

echo "== Gateway disabled (default): no Gateway API resource is rendered =="
expect_failure "no ListenerSet by default" render_only "$LISTENERSET"
expect_failure "no HTTPRoute by default" render_only "$HTTPROUTE"
expect_failure "no BackendTLSPolicy by default" render_only "$BACKENDTLSPOLICY"

echo "== Gateway enabled without parentRef.name must fail fast =="
expect_failure "missing parentRef.name" render --set dashboard.gateway.enabled=true

echo "== HTTP backend, attached via a chart-managed ListenerSet =="
gw_args=(--set dashboard.gateway.enabled=true --set dashboard.gateway.parentRef.name=my-gw)
out=$(render_only "$LISTENERSET" "${gw_args[@]}")
assert_contains "listener protocol is HTTP" "$out" "protocol: HTTP"
out=$(render_only "$HTTPROUTE" "${gw_args[@]}")
assert_contains "HTTPRoute parentRef targets the ListenerSet" "$out" "kind: ListenerSet"

echo "== Gateway enabled with edge TLS disabled never needs tls.secretName =="
expect_success "tls.enabled=false, certificate.create=false, no secretName" \
  render_only "$LISTENERSET" "${gw_args[@]}" --set dashboard.gateway.tls.enabled=false --set dashboard.gateway.tls.certificate.create=false

echo "== HTTPS backend (dashboard.enable_ssl) requires backendTLS.caCertificateRef.name =="
expect_failure "missing backendTLS.caCertificateRef.name" render "${gw_args[@]}" --set dashboard.enable_ssl=true

backend_tls_args=("${gw_args[@]}" --set dashboard.enable_ssl=true --set dashboard.gateway.backendTLS.caCertificateRef.name=dashboard-ca-bundle)
out=$(render_only "$BACKENDTLSPOLICY" "${backend_tls_args[@]}")
assert_contains "BackendTLSPolicy CA ref is a ConfigMap" "$out" "kind: ConfigMap"
assert_contains "BackendTLSPolicy CA ref name is passed through" "$out" "name: dashboard-ca-bundle"
assert_contains "BackendTLSPolicy hostname matches the dashboard certificate SAN" "$out" "hostname: test-wazuh-dashboard"

echo "== Edge TLS: a generated Certificate requires tls.issuerRef.name =="
expect_failure "missing tls.issuerRef.name" render "${gw_args[@]}" --set dashboard.gateway.tls.enabled=true

edge_tls_args=("${gw_args[@]}" --set dashboard.gateway.tls.enabled=true --set dashboard.gateway.tls.issuerRef.name=my-issuer)
out=$(render_only "$GATEWAY_CERTIFICATE" "${edge_tls_args[@]}")
assert_contains "gateway edge Certificate is rendered" "$out" "name: test-wazuh-dashboard-letsencrypt"
out=$(render_only "$LISTENERSET" "${edge_tls_args[@]}")
assert_contains "listener uses HTTPS" "$out" "protocol: HTTPS"

echo "== Edge TLS: certificate.create=false requires tls.secretName =="
expect_failure "missing tls.secretName" render "${gw_args[@]}" --set dashboard.gateway.tls.enabled=true --set dashboard.gateway.tls.certificate.create=false

echo "== Edge TLS: an existing Secret skips Certificate creation =="
existing_secret_args=("${gw_args[@]}" --set dashboard.gateway.tls.enabled=true --set dashboard.gateway.tls.certificate.create=false --set dashboard.gateway.tls.secretName=my-existing-secret)
out=$(render_only "$LISTENERSET" "${existing_secret_args[@]}")
assert_contains "listener references the existing secret" "$out" "name: my-existing-secret"
expect_failure "no Certificate is generated" render_only "$GATEWAY_CERTIFICATE" "${existing_secret_args[@]}"

echo "== Direct Gateway attachment (dashboard.gateway.listenerSet.enabled=false) =="
direct_attach_args=("${gw_args[@]}" --set dashboard.gateway.listenerSet.enabled=false)
expect_failure "no ListenerSet is rendered" render_only "$LISTENERSET" "${direct_attach_args[@]}"
out=$(render_only "$HTTPROUTE" "${direct_attach_args[@]}")
assert_contains "HTTPRoute parentRef targets the Gateway directly" "$out" "kind: Gateway"
assert_contains "HTTPRoute parentRef name is the parent Gateway" "$out" "name: my-gw"

echo "== Ingress and Gateway can coexist =="
coexist_args=(--set dashboard.ingress.enabled=true "${gw_args[@]}")
out=$(render_only "$INGRESS" "${coexist_args[@]}")
assert_contains "Ingress is still rendered" "$out" "kind: Ingress"
out=$(render_only "$HTTPROUTE" "${coexist_args[@]}")
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
out=$(render_only "$INDEXER_SECURITYCONFIG" -f /tmp/wazuh-render-test-173-values.yaml)
assert_contains "internalUsers.hash is templated to the actual password hash" "$out" \
  "hash: '\$2a\$12\$zGWIT7wkPKT/zww3bmMyp.KuWXH4RzgxiB91Q8NGFcqpyPy.R2Rcq'"
rm -f /tmp/wazuh-render-test-173-values.yaml

echo
echo "==================================="
echo "PASS: $pass  FAIL: $fail"
[ "$fail" -eq 0 ]
