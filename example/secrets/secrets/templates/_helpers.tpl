{{- if false }}
{{- end }}

{{- define "encodePullSecret" }}
{{- printf "{\"%s\": {\"username\": \"%s\",\"password\": \"%s\",\"email\": \"%s\",\"auth\": \"%s\"}}" .Values.dockerRegistry.url .Values.dockerRegistry.user .Values.dockerRegistry.pass .Values.dockerRegistry.mail (printf "%s:%s" .Values.dockerRegistry.user .Values.dockerRegistry.pass | b64enc) | b64enc }}
{{- end }}

{{- define "encodePullSecretToJson" }}
{{- printf "{\"auths\":{\"%s\":{\"username\":\"%s\",\"password\":\"%s\",\"email\":\"%s\",\"auth\":\"%s\"}}}" .Values.dockerRegistry.url .Values.dockerRegistry.user .Values.dockerRegistry.pass .Values.dockerRegistry.mail (printf "%s:%s" .Values.dockerRegistry.user .Values.dockerRegistry.pass | b64enc) | b64enc }}
{{- end }}
