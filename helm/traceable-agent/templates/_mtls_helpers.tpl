{{/* These helpers are used to handle determining which source, if any of mTLS certs should be added to a deployment */}}

{{/*
Remote TLS client cert file name
*/}}
{{- define "mtlsHelper.ClientCertFileName" -}}
{{- if .Values.remoteClientCert }}
{{- print "/conf/remote/client-certs/client-cert.pem" }}
{{- else if .Values.remoteClientCertKeySecret.secretName }}
{{- printf "/conf/remote/client-certs/%s" .Values.remoteClientCertKeySecret.clientCertName }}
{{- else if .Values.remoteClientCertFile }}
{{- print .Values.remoteClientCertFile }}
{{- else }}
{{- print "" }}
{{- end }}
{{- end -}}

{{/*
Remote TLS client key file name
*/}}
{{- define "mtlsHelper.ClientKeyFileName" -}}
{{- if .Values.remoteClientKey }}
{{- print "/conf/remote/client-certs/client-key.pem" }}
{{- else if .Values.remoteClientCertKeySecret.secretName }}
{{- printf "/conf/remote/client-certs/%s" .Values.remoteClientCertKeySecret.clientKeyName }}
{{- else if .Values.remoteClientKeyFile }}
{{- print .Values.remoteClientKeyFile }}
{{- else }}
{{- print "" }}
{{- end }}
{{- end -}}

{{/*
Add Remote TLS client cert volumes to container.
- True if both remoteClientCert and remoteClientKey are set, or if remoteClientCertKeySecret is properly configured.
- False for scenarios where users specify absolute path to file or if the required information is missing.
*/}}
{{- define "mtlsHelper.AddClientTlsCertKeyVolume" -}}
{{- if or (and .Values.remoteClientCert .Values.remoteClientKey) (and .Values.remoteClientCertKeySecret.secretName .Values.remoteClientCertKeySecret.clientCertName .Values.remoteClientCertKeySecret.clientKeyName) }}
{{- print "true" }}
{{- else }}
{{- print "false" }}
{{- end }}
{{- end -}}

{{/*
Client TLS certificate and key secret name.
Only valid when both remoteClientCert and remoteClientKey are set or remoteClientCertKeySecret is set
*/}}
{{- define "mtlsHelper.ClientTlsCertKeySecretName" -}}
{{- if and .Values.remoteClientCert .Values.remoteClientKey }}
{{- printf "%s-client-tls" .Chart.Name }}
{{- else if .Values.remoteClientCertKeySecret }}
{{- printf "%s" .Values.remoteClientCertKeySecret.secretName }}
{{- end }}
{{- end -}}