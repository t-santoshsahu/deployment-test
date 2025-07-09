{{/*
Add certificates
If injector is enabled OR tlsEnabled is true
*/}}
{{- define "addTlsCerts" -}}
{{- if or .Values.injectorEnabled .Values.tlsEnabled }}
{{- print "true" }}
{{- else }}
{{- print "false" }}
{{- end }}
{{- end -}}

{{/*
TLS certs mode could be one of the following in order of priority:
- external_tls_files: external tls files injected into the container/image. The customer takes care of the injection. We just need
  to the filepaths.
- external_tls_secret: external tls files as a secret. The secret can be mounted to the container just like in self generated certificates.
- external_tls_strings: base64 encoded tls file contents, these are added to a secret and added to tpa container volume mounts
- self_gen: self generated certificates where during helm install or upgrade, the certificates are generated.
*/}}
{{- define "tlsCertsMode" -}}
{{- if and .Values.tlsPrivateCertificatesAsFiles .Values.tlsPrivateCertificatesAsFiles.rootCAFileName .Values.tlsPrivateCertificatesAsFiles.certFileName .Values.tlsPrivateCertificatesAsFiles.keyFileName }}
{{- print "external_tls_files" }}
{{- else if and .Values.tlsPrivateCertificatesAsSecret .Values.tlsPrivateCertificatesAsSecret.secretName .Values.tlsPrivateCertificatesAsSecret.rootCAFileName .Values.tlsPrivateCertificatesAsSecret.certFileName .Values.tlsPrivateCertificatesAsSecret.keyFileName }}
{{- print "external_tls_secret" }}
{{- else if and .Values.tlsPrivateCertificatesAsString .Values.tlsPrivateCertificatesAsString.rootCAB64 .Values.tlsPrivateCertificatesAsString.certB64 .Values.tlsPrivateCertificatesAsString.keyB64 }}
{{- print "external_tls_strings" }}
{{- else }}
{{- print "self_gen" }}
{{- end }}
{{- end -}}

{{/*
Add TLS certs volumes to container.
- True if addTlsCerts is also true and for the external_tls_secret, external_tls_string and self_gen tls modes.
- False for all other scenarios including external_tls_files since the files are injected into the container.
*/}}
{{- define "addTlsCertVolume" -}}
{{- if and (eq (include "addTlsCerts" .) "true") (or (eq (include "tlsCertsMode" .) "self_gen") (eq (include "tlsCertsMode" .) "external_tls_secret") (eq (include "tlsCertsMode" .) "external_tls_strings")) }}
{{- print "true" }}
{{- else }}
{{- print "false" }}
{{- end }}
{{- end -}}

{{/*
TLS Certs secret name. Only valid for self_gen, external_tls_secret, and external_tls_string tls modes
*/}}
{{- define "tlsCertsSecretName" -}}
{{- if eq (include "tlsCertsMode" .) "external_tls_secret" }}
{{- print .Values.tlsPrivateCertificatesAsSecret.secretName }}
{{- else if eq (include "tlsCertsMode" .) "external_tls_strings" }}
{{- print "traceable-agent-cert" }}
{{- else }}
{{- printf "%s-cert" .Chart.Name }}
{{- end }}
{{- end -}}

{{/*
TLS Key file name by TLS mode
*/}}
{{- define "tlsKeyFileName" -}}
{{- if eq (include "tlsCertsMode" .) "external_tls_files" }}
{{- print .Values.tlsPrivateCertificatesAsFiles.keyFileName }}
{{- else if eq (include "tlsCertsMode" .) "external_tls_secret" }}
{{- printf "/conf/certs/%s" .Values.tlsPrivateCertificatesAsSecret.keyFileName }}
{{- else }}
{{- print "/conf/certs/tls.key" }}
{{- end }}
{{- end -}}

{{/*
TLS cert file name by TLS mode
*/}}
{{- define "tlsCertFileName" -}}
{{- if eq (include "tlsCertsMode" .) "external_tls_files" }}
{{- print .Values.tlsPrivateCertificatesAsFiles.certFileName }}
{{- else if eq (include "tlsCertsMode" .) "external_tls_secret" }}
{{- printf "/conf/certs/%s" .Values.tlsPrivateCertificatesAsSecret.certFileName }}
{{- else }}
{{- print "/conf/certs/tls.crt" }}
{{- end }}
{{- end -}}

{{/*
TLS root cert file name by TLS mode
*/}}
{{- define "tlsRootCaCertFileName" -}}
{{- if eq (include "tlsCertsMode" .) "external_tls_files" }}
{{- print .Values.tlsPrivateCertificatesAsFiles.rootCAFileName }}
{{- else if eq (include "tlsCertsMode" .) "external_tls_secret" }}
{{- printf "/conf/certs/%s" .Values.tlsPrivateCertificatesAsSecret.rootCAFileName }}
{{- else }}
{{- print "/conf/certs/root_ca.crt" }}
{{- end }}
{{- end -}}

{{/*
Traceable agent cert secret template. Used in both daemonset and deployment.
*/}}
{{- define "certSecretTemplate" -}}
{{- $top := index . 0 -}}
{{- $certKey := index . 1 "certKey" -}}
{{- $certCert := index . 1 "certCert" -}}
{{- $caBundle := index . 1 "caBundle" }}
apiVersion: v1
kind: Secret
metadata:
  name: {{ include "tlsCertsSecretName" $top }}
  namespace: {{ $top.Release.Namespace }}
  labels:
{{ include "traceableai.labels" $top | indent 4 }}
  annotations:
{{ include "traceableai.annotations" $top | indent 4 }}
type: Opaque
# Values are expected to be base64 encoded already
data:
  tls.key: {{ $certKey }}
  tls.crt: {{ $certCert }}
  root_ca.crt: {{ $caBundle }}
---
{{- end -}}