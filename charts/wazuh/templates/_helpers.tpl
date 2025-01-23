{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "wazuh.name" -}}
{{ include "appIdentifier" .Values.identifier }}-wazuh
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
*/}}
{{- define "wazuh.fullname" -}}
{{ include "appIdentifier" .Values.identifier }}-wazuh
{{- end -}}
{{/*
Create a fully qualified elasticsearch name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
*/}}
{{- define "wazuh.indexer.name" -}}
{{ include "appIdentifier" .Values.identifier }}-indexer
{{- end -}}

{{- define "wazuh.indexer.fullname" -}}
{{ include "appIdentifier" .Values.identifier }}-indexer
{{- end -}}


{{- define "wazuh.dashboard.name" -}}
{{ include "appIdentifier" .Values.identifier }}-dashboard
{{- end -}}
{{/*
Create a fully qualified kibana name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
*/}}
{{- define "wazuh.dashboard.fullname" -}}
{{ include "appIdentifier" .Values.identifier }}-dashboard
{{- end -}}

{{/*
Create a fully qualified Wazuh Agent DaemonSet name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
*/}}
{{- define "wazuh.agent.name" -}}
{{ include "appIdentifier" .Values.identifier }}-agent
{{- end -}}

{{- define "wazuh.agent.fullname" -}}
{{ include "appIdentifier" .Values.identifier }}-agent
{{- end -}}

{{/*
Create the name of the service account to use for the agent daemonset
*/}}
{{- define "wazuh.serviceAccountName.agent" -}}
{{- if .Values.agent.serviceAccount.create -}}
{{ default (include "wazuh.agent.fullname" .)  .Values.agent.serviceAccount.name }}
{{- else -}}
{{ default "default" .Values.agent.serviceAccounts.alertmanager.name }}
{{- end -}}
{{- end -}}

{{/* vim: set filetype=mustache: */}}
{{/*
Builds the full AppIdentifier, which is used for Kubernetes Objects
*/}}
{{- define "appIdentifier" -}}
{{ .appName }}-{{ .appId }}
{{- end -}}

{{/*
Builds the full SpaceIdentifier, which is used for Namespaces
*/}}
{{- define "spaceIdentifier" -}}
{{ .spaceName }}-{{ .spaceId }}
{{- end -}}

{{/*
Builds the full DNS of a Service
*/}}
{{- define "serviceName" -}}
{{ template "appIdentifier" }}.{{ template "spaceIdentifier" }}
{{- end -}}

{{- define "dynamicEnvTemplate" -}}
{{- with .Values.api.config.envReplacement }}
{{ tpl . $ | indent 10 }}
{{- end -}}
{{- end -}}

{{- define "annotations" -}}
appId: {{ .Values.identifier.appId }}
appName: {{ .Values.identifier.appName }}
{{- end -}}

{{- define "labels" -}}
appId: {{ .Values.identifier.appId }}
appName: {{ .Values.identifier.appName }}
{{- end -}}

