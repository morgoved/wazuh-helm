{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "wazuh.name" -}}
{{- default "wazuh" .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
*/}}
{{- define "wazuh.fullname" -}}
  {{- if .Values.fullnameOverride -}}
    {{ .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
  {{- else -}}
    {{- $name := default "wazuh" .Values.nameOverride -}}
    {{- if contains $name .Release.Name -}}
      {{- .Release.Name | trunc 63 | trimSuffix "-" -}}
    {{- else -}}
      {{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
    {{- end -}}
  {{- end -}}
{{- end -}}

{{- define "wazuh.indexer.fullname" -}}
  {{- if .Values.indexer.fullnameOverride -}}
    {{ .Values.indexer.fullnameOverride | trunc 63 | trimSuffix "-" }}
  {{- else -}}
    {{ include "wazuh.fullname" . }}
  {{- end -}}
{{- end -}}

{{- define "wazuh.dashboard.username" -}}
{{- if .Values.dashboard.cred.existingSecret -}}
  {{- $secret := lookup "v1" "Secret" .Release.Namespace .Values.dashboard.cred.existingSecret -}}
  {{- if and $secret (index $secret.data "DASHBOARD_USERNAME") -}}
    {{- index $secret.data "DASHBOARD_USERNAME" | b64dec -}}
  {{- else -}}
    {{- .Values.dashboard.cred.username -}}
  {{- end -}}
{{- else -}}
  {{- .Values.dashboard.cred.username -}}
{{- end -}}
{{- end -}}

{{- define "wazuh.dashboard.passwordHash" -}}
{{- if .Values.dashboard.cred.existingSecret -}}
  {{- $secret := lookup "v1" "Secret" .Release.Namespace .Values.dashboard.cred.existingSecret -}}
  {{- if and $secret (index $secret.data "DASHBOARD_PASSWORD_HASH") -}}
    {{- index $secret.data "DASHBOARD_PASSWORD_HASH" | b64dec -}}
  {{- else -}}
    {{- .Values.dashboard.cred.passwordHash -}}
  {{- end -}}
{{- else -}}
  {{- .Values.dashboard.cred.passwordHash -}}
{{- end -}}
{{- end -}}

{{- define "wazuh.indexer.passwordHash" -}}
{{- if .Values.indexer.cred.existingSecret -}}
  {{- $secret := lookup "v1" "Secret" .Release.Namespace .Values.indexer.cred.existingSecret -}}
  {{- if and $secret (index $secret.data "INDEXER_PASSWORD_HASH") -}}
    {{- index $secret.data "INDEXER_PASSWORD_HASH" | b64dec -}}
  {{- else -}}
    {{- .Values.indexer.cred.passwordHash -}}
  {{- end -}}
{{- else -}}
  {{- .Values.indexer.cred.passwordHash -}}
{{- end -}}
{{- end -}}

{{- define "wazuh.dashboard.config"}}
server.host: 0.0.0.0
server.port: {{ .Values.dashboard.service.httpPort }}

{{- if .Values.indexer.enabled }}
opensearch.hosts: "https://{{ include "wazuh.indexer.fullname" . }}-indexer:{{ .Values.indexer.service.httpPort }}"
{{- else if .Values.externalIndexer.enabled }}
opensearch.hosts: "{{ .Values.externalIndexer.host }}:{{ .Values.externalIndexer.port }}"
{{- else }}
{{- fail "Please enable either .Values.indexer.enabled or .Values.externalIndexer.enabled" }}
{{- end }}

opensearch.ssl.verificationMode: none
opensearch.requestHeadersWhitelist: [ authorization,securitytenant ]
opensearch_security.multitenancy.enabled: false
opensearch_security.readonly_mode.roles: ["kibana_read_only"]
opensearch_security.auth.unauthenticated_routes: ['/api/stats', '/api/status']
server.ssl.enabled: {{ .Values.dashboard.enable_ssl }}
server.ssl.key: "/usr/share/wazuh-dashboard/certs/key.pem"
server.ssl.certificate: "/usr/share/wazuh-dashboard/certs/cert.pem"
opensearch.ssl.certificateAuthorities: ["/usr/share/wazuh-dashboard/certs/root-ca.pem"]
uiSettings.overrides.defaultRoute: /app/wz-home

{{- $authType := list }}
{{- if .Values.dashboard.sso.oidc.enabled }}
{{-   $authType = append $authType "openid" }}
{{- end }}
{{- if .Values.dashboard.sso.saml.enabled }}
{{-   $authType = append $authType "saml" }}
{{- end }}
{{- if .Values.dashboard.basicAuth.enabled }}
{{-   $authType = append $authType "basicauth" }}
{{- end }}
opensearch_security.auth.multiple_auth_enabled: {{ gt ($authType | len) 1 }}
opensearch_security.auth.type: {{ $authType | toJson }}

{{- if .Values.dashboard.sso.oidc.enabled }}
{{- $baseRedirectUrl := .Values.dashboard.sso.oidc.baseRedirectUrl | default .Values.dashboard.ingress.host }}
opensearch_security.openid.connect_url: {{ required "dashboard.sso.oidc.url is required" .Values.dashboard.sso.oidc.url }}
opensearch_security.openid.logout_url: {{ required "dashboard.sso.oidc.logoutUrl is required" .Values.dashboard.sso.oidc.logoutUrl }}
opensearch_security.openid.base_redirect_url: {{ required "dashboard.sso.oidc.baseRedirectUrl is required" $baseRedirectUrl }}
opensearch_security.openid.scope: {{ .Values.dashboard.sso.oidc.scope }}
opensearch_security.openid.client_id: ${OPENSEARCH_OIDC_CLIENT_ID}
opensearch_security.openid.client_secret: ${OPENSEARCH_OIDC_CLIENT_SECRET}

{{- if .Values.dashboard.sso.oidc.customizeLoginButton.enabled }}
opensearch_security.ui.openid.login.buttonname: {{ .Values.dashboard.sso.oidc.customizeLoginButton.text }}
{{- if .Values.dashboard.sso.oidc.customizeLoginButton.showImage }}
opensearch_security.ui.openid.login.brandimage: {{ required "dashboard.sso.oidc.customizeLoginButton.imageUrl is required" .Values.dashboard.sso.oidc.customizeLoginButton.imageUrl }}
opensearch_security.ui.openid.login.showbrandimage: {{ .Values.dashboard.sso.oidc.customizeLoginButton.showImage }}
{{- end }}
{{- end }}
{{- end }}

{{- if .Values.dashboard.sso.saml.enabled }}
server.xsrf.allowlist: ["/_plugins/_security/saml/acs", "/_plugins/_security/saml/logout", "/_opendistro/_security/saml/logout", "/_opendistro/_security/api/authtoken", "/_opendistro/_security/saml/acs", "/_opendistro/_security/saml/acs/idpinitiated", "/_plugins/_security/api/authtoken"]
opensearch_security.session.keepalive: false
{{- end }}

{{- if .Values.dashboard.server.extraConf }}
{{ toYaml .Values.dashboard.server.extraConf }}
{{- end }}

{{- end }}

{{/*
Sysctl set if less then
*/}}
{{- define "wazuh.sysctlIfLess" -}}
CURRENT=`sysctl -n {{ .key }}`;
DESIRED="{{ .value }}";
if [ "$DESIRED" -gt "$CURRENT" ]; then
    sysctl -w {{ .key }}={{ .value }};
fi;
{{- end -}}

{{/*
Get port value from ports array by name
*/}}
{{- define "wazuh.getPortByName" -}}
{{- $portName := .portName -}}
{{- $ports := .ports -}}
{{- range $ports -}}
{{- if eq .name $portName -}}
{{- .port -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Define serviceaccount names
*/}}
{{- define "wazuh.indexer.serviceAccountName" -}}
{{- if .Values.indexer.serviceAccount.create -}}
    {{ default (printf "%s-indexer" (include "wazuh.indexer.fullname" .)) .Values.indexer.serviceAccount.name }}
{{- else -}}
    {{ "default" }}
{{- end -}}
{{- end -}}

{{- define "wazuh.dashboard.serviceAccountName" -}}
{{- if .Values.dashboard.serviceAccount.create -}}
    {{ default (printf "%s-dashboard" (include "wazuh.fullname" .)) .Values.dashboard.serviceAccount.name }}
{{- else -}}
    {{ "default" }}
{{- end -}}
{{- end -}}

{{- define "wazuh.manager.serviceAccountName" -}}
{{- if .Values.wazuh.serviceAccount.create -}}
    {{ default (printf "%s-manager" (include "wazuh.fullname" .)) .Values.wazuh.serviceAccount.name }}
{{- else -}}
    {{ "default" }}
{{- end -}}
{{- end -}}

{{- define "wazuh.agent.serviceAccountName" -}}
{{- if .Values.agent.serviceAccount.create -}}
    {{ default (printf "%s-agent" (include "wazuh.fullname" .)) .Values.agent.serviceAccount.name }}
{{- else -}}
    {{ "default" }}
{{- end -}}
{{- end -}}
