{{- define "grpcToHttpContainerTemplate" -}}
- name: traceable-grpc-to-http
  image: {{.Values.imageCredentials.registry}}/{{.Values.grpcToHttp.image}}
  args:
    - "--config-path"
    - "/etc/envoy/envoy.yaml"
  ports:
    - containerPort: {{ .Values.grpcToHttp.port }}
  resources:
{{- toYaml .Values.grpcToHttp.resources | nindent 4 }}
  volumeMounts:
    - name: config-volume
      mountPath: /etc/envoy/envoy.yaml
      subPath: envoy.yaml
      readOnly: true
{{- if .Values.grpcToHttp.serverCertSecretName }}
    - name: server-cert
      mountPath: /etc/certs/server.crt
      subPath: server.crt
      readOnly: true
{{- end }}
{{- if .Values.grpcToHttp.serverKeySecretName }}
    - name: server-key
      mountPath: /etc/certs/server.key
      subPath: server.key
      readOnly: true
{{- end }}
{{- if and .Values.useCustomSecurityContext (or .Values.grpcToHttpContainerSecurityContext .Values.commonContainerSecurityContext) }}
  securityContext:
{{- if .Values.grpcToHttpContainerSecurityContext }}
{{- toYaml .Values.grpcToHttpContainerSecurityContext | nindent 4 }}
{{- else }}
{{- toYaml .Values.commonContainerSecurityContext | nindent 4 }}
{{- end }}
{{- end }}
{{- end -}}

{{- define "grpcToHttp.volumes" -}}
- name: config-volume
  configMap:
    name: {{ .Release.Name }}-grpc-to-http-configmap
{{- if .Values.grpcToHttp.serverCertSecretName }}
- name: server-cert
  secret:
    secretName: {{ .Values.grpcToHttp.serverCertSecretName }}
{{- end }}
{{- if .Values.grpcToHttp.serverKeySecretName }}
- name: server-key
  secret:
    secretName: {{ .Values.grpcToHttp.serverKeySecretName }}
{{- end }}
{{- end -}}