#!/usr/bin/env bash
# Consistency checks between values.yaml, values.schema.json and the templates.
#
# 1. values.schema.json is up to date with values.yaml (`helm schema` from the repo root).
# 2. Every `.Values.<path>` read by a template is declared in the schema, so a key
#    the chart uses can never be rejected by the schema (and is documented in values.yaml).
# 3. The schema rejects unknown keys (typos) and accepts the default values.
#
# Usage: charts/wazuh/tests/schema_test.sh
# Requires: helm with the schema plugin (https://github.com/losisin/helm-values-schema-json), jq.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHART_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_DIR="$(cd "$CHART_DIR/../.." && pwd)"
SCHEMA="$CHART_DIR/values.schema.json"

pass=0
fail=0

ok() { echo "PASS: $1"; pass=$((pass + 1)); }
ko() { echo "FAIL: $1"; fail=$((fail + 1)); }

# 1. Schema is up to date.
tmp_schema="$(mktemp)"
if (cd "$REPO_DIR" && helm schema --output "$tmp_schema" >/dev/null) && diff -u "$SCHEMA" "$tmp_schema"; then
  ok "values.schema.json is up to date"
else
  ko "values.schema.json is out of date: run 'helm schema' from the repository root"
fi
rm -f "$tmp_schema"

# 2. Every .Values path used by the templates is declared in the schema.
# A path is declared if each segment is a property, or if an ancestor allows
# additional properties (free-form maps such as annotations or resources).
declared() {
  jq -e --arg path "$1" '
    def walk_path($node; $segs):
      if ($segs | length) == 0 then true
      elif ($node.properties[$segs[0]] // null) != null then walk_path($node.properties[$segs[0]]; $segs[1:])
      elif ($node.additionalProperties // false) != false then true
      else false end;
    walk_path(.; $path | split("."))
  ' "$SCHEMA" >/dev/null
}

missing=()
while read -r path; do
  declared "$path" || missing+=("$path")
done < <(grep -rhoE '\.Values(\.[A-Za-z0-9_]+)+' "$CHART_DIR/templates" | sed 's/^\.Values\.//' | sort -u)

if [ "${#missing[@]}" -eq 0 ]; then
  ok "every .Values path used in templates is declared in values.yaml"
else
  ko "paths used in templates but missing from values.yaml: ${missing[*]}"
fi

# 3. The schema accepts the defaults and rejects unknown keys.
helm dependency build "$CHART_DIR" >/dev/null
if helm template test "$CHART_DIR" >/dev/null 2>&1; then
  ok "default values pass the schema"
else
  ko "default values fail the schema"
fi
if helm template test "$CHART_DIR" --set dashboard.replica=2 >/dev/null 2>&1; then
  ko "unknown key dashboard.replica should be rejected"
else
  ok "unknown key dashboard.replica is rejected"
fi
if helm template test "$CHART_DIR" --set wazuh.master.resources.limits.ephemeral-storage=1Gi \
  --set 'agent.tolerations[0].operator=Exists' --set dashboard.annotations.foo=bar >/dev/null 2>&1; then
  ok "free-form Kubernetes fields are accepted"
else
  ko "free-form Kubernetes fields should be accepted"
fi

echo
echo "==================================="
echo "PASS: $pass  FAIL: $fail"
[ "$fail" -eq 0 ]
