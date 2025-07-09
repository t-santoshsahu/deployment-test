{{/*
Common labels & additional user provided labels
*/}}
{{- define "traceableai.labels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
helm.sh/chart: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- if .Values.additionalGlobalLabels }}
{{- toYaml .Values.additionalGlobalLabels | nindent 0 }}
{{- end }}
{{- end }}

{{- define "traceableai.only.global.labels" -}}
{{- if .Values.additionalGlobalLabels }}
{{- toYaml .Values.additionalGlobalLabels | nindent 0 }}
{{- end }}
{{- end }}

{{- define "tpaImageVersion" -}}
{{- if ne .Values.imageVersion "" }}
{{- .Values.imageVersion }}
{{- else -}}
{{- .Chart.AppVersion }}
{{- end -}}
{{- end -}}

{{/*
Additional annotations to add to the deployment
*/}}
{{- define "traceableai.additionalAnnotations" -}}
{{- if .Values.additionalAnnotations }}
{{- toYaml .Values.additionalAnnotations }}
{{- end }}
{{- end -}}

{{/*
Annotations applied to all resources
*/}}
{{- define "traceableai.annotations" -}}
{{- if and .Values.additionalGlobalAnnotations (not (empty .Values.additionalGlobalAnnotations)) }}
{{- toYaml .Values.additionalGlobalAnnotations }}
{{- end }}
{{- end }}

{{/*
Binary check for if a token file has been provider
*/}}
{{- define "refreshTokenFilePresent" -}}
{{ gt (len .Values.refreshTokenFile) 0 }}
{{- end }}

{{/*
Bootstrap token from GCP
*/}}
{{- define "bootstrapRefreshTokenFromGcp" -}}
{{- if and (.Values.refreshTokenGcpSecretProject) (.Values.refreshTokenGcpSecretName) }}
{{- if and (ne .Values.refreshTokenGcpSecretProject "") (ne .Values.refreshTokenGcpSecretName "") }}
{{- true }}
{{- else }}
{{- false}}
{{- end }}
{{- else }}
{{- false }}
{{- end }}
{{- end -}}

{{/*
Additional annotations to add to the serviceaccount
*/}}
{{- define "serviceAccountAnnotations" -}}
{{- if and (.Values.gkeServiceAccount) (gt (len .Values.gkeServiceAccount) 0) }}
iam.gke.io/gcp-service-account: {{ .Values.gkeServiceAccount }}
{{- end }}
{{- end -}}

{{/*
Regcred Secret
- If we are not creating k8s manifests and image registry username and password are not empty,
  regcredSecretName is prefixed with the .values.imageCredentials.registry. Otherwise, it's an empty string.
  We replace "/" with "-" in the registry because of k8s resource name requirements.
*/}}
{{- define "regcredSecretName" -}}
{{- if and (not .Values.k8sManifests) (ne .Values.imageCredentials.username "") (ne .Values.imageCredentials.password "") }}
{{- printf "%s-regcred" .Values.imageCredentials.registry | replace "/" "-"}}
{{- else if .Values.imagePullSecretName }}
{{- .Values.imagePullSecretName }}
{{- else }}
{{- print "" }}
{{- end }}
{{- end -}}

{{/*
Use external token secret
*/}}
{{- define "useExternalTokenSecret" -}}
{{- if .Values.externalTokenSecret }}
{{- if and (.Values.externalTokenSecret.name) (.Values.externalTokenSecret.key) }}
{{- if and (ne .Values.externalTokenSecret.name "") (ne .Values.externalTokenSecret.key "") }}
{{- true }}
{{- else }}
{{- false}}
{{- end }}
{{- else }}
{{- false }}
{{- end }}
{{- else }}
{{- false }}
{{- end }}
{{- end -}}



{{/*
Receivers
*/}}
{{- define "collectorTracesReceivers" -}}
{{- $collectorTracesReceiversString := printf "" -}}
{{- $otlpReceiver := include "collectorOtlpReceiver" . }}
{{- $collectorTracesReceiversString := printf "%s%s" $collectorTracesReceiversString $otlpReceiver -}}
{{- $zipkinReceiver := include "collectorZipkinReceiver" . }}
{{- $collectorTracesReceiversString := printf "%s%s" $collectorTracesReceiversString $zipkinReceiver -}}
{{- printf "[%s]" $collectorTracesReceiversString -}}
{{- end -}}

{{- define "collectorMetricsReceivers" -}}
{{- $collectorMetricsReceivers1 := printf "" -}}
{{- $otlpReceiver := include "collectorOtlpReceiver" . }}
{{- $collectorMetricsReceivers1 := printf "%s%s" $collectorMetricsReceivers1 $otlpReceiver -}}
{{- printf "[%sprometheus]" $collectorMetricsReceivers1 -}}
{{- end -}}

{{- define "collectorOtlpReceiver" -}}
{{- if .Values.collector.receivers.otlp.enabled }}
{{- printf "otlp, " -}}
{{- else -}}
{{- printf ""}}
{{- end }}
{{- end -}}

{{- define "collectorZipkinReceiver" -}}
{{- if .Values.collector.receivers.zipkin.enabled }}
{{- printf "zipkin, " -}}
{{- else -}}
{{- printf ""}}
{{- end }}
{{- end -}}

{{/*
Processors for the traces pipeline. The order matters for processors. Here's how they are ordered when all the ones supported are
enabled:
[k8sattributes, traceable_servicenamerprocessor, traceable_spanremover, traceable_traces_buffer, traceable_barespanconverter,
 traceable_ipresolutionprocessor, traceable_protoprocessor, traceable_base64decoderprocessor, traceable_dataparser, traceable_dataclassification,
 traceable_modsec, traceable_metadata, batch]
*/}}
{{- define "collectorProcessors" -}}
{{- $collectorProcessors1 := printf "" -}}
{{- $k8sAttributes := include "collectorK8sProcessor" . }}
{{- $collectorProcessors1 := printf "%s%s" $collectorProcessors1 $k8sAttributes -}}
{{- $serviceNamerProcessor := include "collectorServiceNamerProcessor" . }}
{{- $collectorProcessors1 := printf "%s%s" $collectorProcessors1 $serviceNamerProcessor -}}
{{- $spanRemover := include "spanRemoverProcessor" . }}
{{- $collectorProcessors1 := printf "%s%s" $collectorProcessors1 $spanRemover -}}
{{- $tracesBufferingProcessor := include "tracesBufferingProcessor" . }}
{{- $collectorProcessors1 := printf "%s%s" $collectorProcessors1 $tracesBufferingProcessor -}}
{{- if .Values.additionalTracePreprocessorPipeline -}}
  {{- range $processor := .Values.additionalTracePreprocessorPipeline -}}
    {{- $collectorProcessors1 = printf "%s%s, " $collectorProcessors1 $processor -}}
  {{- end -}}
{{- end -}}
{{- $bareSpanConverter := include "bareSpanConverterProcessor" . }}
{{- $collectorProcessors1 := printf "%s%s" $collectorProcessors1 $bareSpanConverter -}}
{{- $ipResolutionProcessor := include "ipResolutionProcessor" .}}
{{- $collectorProcessors1 := printf "%s%s" $collectorProcessors1 $ipResolutionProcessor -}}
{{- $protoprocessor := include "collectorProtoprocessor" . }}
{{- $collectorProcessors1 := printf "%s%s" $collectorProcessors1 $protoprocessor -}}
{{- $base64DecoderProcessor := include "collectorBase64DecoderProcessor" . }}
{{- $collectorProcessors1 := printf "%s%s" $collectorProcessors1 $base64DecoderProcessor -}}
{{- $collectorProcessors1 := printf "%straceable_attributes, " $collectorProcessors1 -}}
{{- $collectorProcessors1 := printf "%straceable_dataparser, " $collectorProcessors1 -}}
{{- $collectorProcessors1 := printf "%straceable_dataclassification, " $collectorProcessors1 -}}
{{- $collectorProcessors1 := printf "%straceable_modsec, " $collectorProcessors1 -}}
{{- $collectorProcessors1 := printf "%straceable_metadata, " $collectorProcessors1 -}}

{{- printf "[%sbatch]" $collectorProcessors1 -}}
{{- end -}}

{{/*
Internal Traces pipeline processors. The order matters for processors.
[transform/environment, filter/internal_spans, batch]
*/}}
{{- define "collectorInternalSpansProcessors" -}}
{{- $collectorInternalSpansProcessor1 := printf "transform/environment, " -}}
{{- $collectorInternalSpansProcessor1 := printf "%sfilter/internal_spans, " $collectorInternalSpansProcessor1 -}}
{{- if .Values.additionalTraceInternalSpanProcessors -}}
  {{- range $processor := .Values.additionalTraceInternalSpanProcessors -}}
    {{- $collectorInternalSpansProcessor1 = printf "%s%s, " $collectorInternalSpansProcessor1 $processor -}}
  {{- end -}}
{{- end -}}
{{- printf "[%sbatch]" $collectorInternalSpansProcessor1 -}}
{{- end -}}

{{- define "bareSpanConverterProcessor" -}}
{{- if .Values.bareSpanConverterProcessor }}
{{- printf "traceable_barespanconverter, " -}}
{{- else -}}
{{- printf ""}}
{{- end }}
{{- end -}}

{{- define "ipResolutionProcessor" -}}
{{- if .Values.ipResolutionProcessor }}
{{- printf "traceable_ipresolutionprocessor, " -}}
{{- else -}}
{{- printf ""}}
{{- end }}
{{- end -}}

{{- define "spanRemoverProcessor" -}}
{{- if .Values.spanRemoverProcessor }}
{{- printf "traceable_spanremover, " -}}
{{- else -}}
{{- printf ""}}
{{- end }}
{{- end -}}

{{- define "collectorK8sProcessor" -}}
{{- if .Values.k8sProcessorEnabled }}
{{- printf "k8sattributes, " -}}
{{- else -}}
{{- printf ""}}
{{- end }}
{{- end -}}

{{- define "collectorServiceNamerProcessor" -}}
{{- if .Values.serviceNamerProcessorEnabled }}
{{- printf "traceable_servicenamerprocessor, " -}}
{{- else -}}
{{- printf ""}}
{{- end }}
{{- end -}}

{{- define "collectorProtoprocessor" -}}
{{- if .Values.protoprocessor }}
{{- printf "traceable_protoprocessor, " -}}
{{- else -}}
{{- printf ""}}
{{- end }}
{{- end -}}

{{- define "collectorBase64DecoderProcessor" -}}
{{- if .Values.base64DecoderProcessor }}
{{- printf "traceable_base64decoderprocessor, " -}}
{{- else -}}
{{- printf ""}}
{{- end }}
{{- end -}}

{{- define "tracesBufferingProcessor" -}}
{{- if .Values.tracesBufferingProcessorEnabled }}
{{- printf "traceable_traces_buffer, " -}}
{{- else -}}
{{- printf ""}}
{{- end }}
{{- end -}}

{{/*
Docker registry secrets
*/}}
{{- define "traceableai.imagePullSecret" }}
{{- with .Values.imageCredentials }}
{{- printf "{\"auths\": {\"%s\": {\"auth\": \"%s\"}}}" .registry (printf "%s:%s" (.username | required "docker username required" ) (.password | required "docker password required ") | b64enc) | b64enc }}
{{- end }}
{{- end }}

{{/*
API token
*/}}
{{- define "traceableai.token" }}
{{- $bootstrapRefreshTokenFromGcp := include "bootstrapRefreshTokenFromGcp" . }}
{{- if and (eq $bootstrapRefreshTokenFromGcp "false") (eq .Values.extCapAuth.enabled false) }}
{{- $tokenValue := .Values.token | required "api token must be specified or passed in a separately created non-empty token secret name and key" }}
{{- printf "%s" $tokenValue }}
{{- end }}
{{- end }}

{{/*
Traceable agent service ports
*/}}
{{- define "traceable-agent.servicePorts" -}}
{{- $addTlsCerts := include "addTlsCerts" . }}
{{- $tlsServerPort := int ( include "tlsServerPort" . ) }}
{{- $podMirroringEnabled := include "podMirroringEnabled" . }}
ports:
{{- if and .Values.singleServiceMode .Values.httpReverseProxyEnabled .Values.loadBalancerHttpsAgentService.enabled (eq .Values.serviceType "LoadBalancer") (not .Values.injectorEnabled) }}
  - port: {{ .Values.loadBalancerHttpsAgentService.port }}
    name: https-agent
    protocol: TCP
    targetPort: {{ .Values.loadBalancerHttpsAgentService.targetPort }}
{{- else if eq $addTlsCerts "true" }}
  - port: {{ $tlsServerPort }}
    name: https-agent
    protocol: TCP
    targetPort: {{ $tlsServerPort }}
{{- if and (eq .Values.serviceType "NodePort") (ne (int .Values.tlsServerNodePort) 0) }}
    nodePort: {{ .Values.tlsServerNodePort }}
{{- end }}
{{- end }}
{{- if not .Values.tlsEnabled }}
{{- if and .Values.singleServiceMode .Values.httpReverseProxyEnabled }}
{{- if not .Values.loadBalancerHttpsAgentService.enabled}}
  - port: {{ .Values.restServerPort }}
    name: grpc-http-agent
    protocol: TCP
    targetPort: {{ .Values.restServerPort }}
{{- if and (eq .Values.serviceType "NodePort") (ne (int .Values.restServerNodePort) 0) }}
    nodePort: {{ .Values.restServerNodePort }}
{{- end }}
{{- end }}
{{- else }}
  - port: {{ .Values.serverPort }}
    name: grpc-agent
    protocol: TCP
    targetPort: {{ .Values.serverPort }}
  - port: {{ .Values.restServerPort }}
{{- if .Values.httpReverseProxyEnabled }}
    name: grpc-http-agent
{{- else }}
    name: http-agent
{{- end }}
    protocol: TCP
    targetPort: {{ .Values.restServerPort }}
{{- if and (eq .Values.serviceType "NodePort") (ne (int .Values.restServerNodePort) 0) }}
    nodePort: {{ .Values.restServerNodePort }}
{{- end }}
{{- if .Values.collectorEnabled }}
{{- if .Values.collector.receivers.otlp.enabled }}
  - port: {{ .Values.collector.ports.opentelemetry }}
    name: grpc-otlp
    protocol: TCP
    targetPort:  {{ .Values.collector.ports.opentelemetry }}
  - port: {{ .Values.collector.ports.opentelemetryHttp }}
    name: http-otlp
    protocol: TCP
    targetPort: {{ .Values.collector.ports.opentelemetryHttp }}
{{- end }}
{{- if .Values.collector.receivers.zipkin.enabled }}
  - port: {{ .Values.collector.ports.zipkin }}
    name: http-zipkin
    protocol: TCP
    targetPort: {{ .Values.collector.ports.zipkin }}
{{- end }}
{{- if .Values.collector.exporters.prometheus.enabled }}
  - port: {{ .Values.collector.ports.prometheus }}
    name: http-prometheus
    protocol: TCP
    targetPort: {{ .Values.collector.ports.prometheus }}
{{- end }}
{{- end }}
{{- end }}
{{- if eq $podMirroringEnabled "true" }}
  - port: 4789
    name: mirroring-vxlan
    protocol: UDP
    targetPort: 4789
{{- end }}
{{- if .Values.extensionService.runWithDeployment }}
  - port: {{.Values.extensionService.port}}
    name: grpc-extensionservice
    protocol: TCP
    targetPort: {{ .Values.extensionService.port }}
{{- end }}
{{- if eq .Values.multipleServices.enabled false }}
{{- if .Values.hslServer.enabled }}
  - port: {{ .Values.hslServer.port }}
    name: tcp-hsl
    protocol: TCP
    targetPort: {{ .Values.hslServer.port }}
{{- end }}
{{- if .Values.apigeeServer.enabled }}
  - port: {{ .Values.apigeeServer.server.port }}
    name: tcp-apigee
    protocol: TCP
    targetPort: {{ .Values.apigeeServer.server.port }}
{{- end }}
{{- end }}
{{- end }}
{{- end -}}

{{/*
Collector service ports
*/}}
{{- define "traceable-agent.collector.ports" -}}
ports:
{{- if .Values.collector.receivers.otlp.enabled }}
  - port: {{ .Values.collector.ports.opentelemetry }}
    name: opentelemetry
    protocol: TCP
    targetPort: {{ .Values.collector.ports.opentelemetry }}
  - port: {{ .Values.collector.ports.opentelemetryHttp }}
    name: opentelemetry-http
    protocol: TCP
    targetPort: {{ .Values.collector.ports.opentelemetryHttp }}
{{- end }}
{{- if .Values.collector.receivers.zipkin.enabled }}
  - port: {{ .Values.collector.ports.zipkin }}
    name: zipkin
    protocol: TCP
    targetPort: {{ .Values.collector.ports.zipkin }}
{{- end }}
{{- if .Values.collector.exporters.prometheus.enabled }}
  - port: {{ .Values.collector.ports.prometheus }}
    name: prometheus
    protocol: TCP
    targetPort: {{ .Values.collector.ports.prometheus }}
{{- end }}
{{- end -}}

{{/*
Injectee Traceable agent image version. Allows an option for one to specify a different version
other than the app version in the chart. Otherwise, it's just Chart.AppVersion
*/}}
{{- define "injecteeTMEImageVersion" -}}
{{- if .Values.injector.tme.imageVersion }}
{{- printf .Values.injector.tme.imageVersion -}}
{{- else -}}
{{- printf .Chart.AppVersion }}
{{- end }}
{{- end -}}

{{/*
Injectee Haproxy init image version. Allows an option for one to specify a different version
other than the app version in the chart. Otherwise, it's just Chart.AppVersion
*/}}
{{- define "injecteeHaproxyImageVersion" -}}
{{- if .Values.injector.haproxy.imageVersion }}
{{- printf .Values.injector.haproxy.imageVersion -}}
{{- else -}}
{{- printf .Chart.AppVersion }}
{{- end }}
{{- end -}}

{{/*
Injectee wasm init image version. Allows an option for one to specify a different version
other than the app version in the chart. Otherwise, it's just Chart.AppVersion
*/}}
{{- define "injecteeWasmImageVersion" -}}
{{- if .Values.injector.wasm.imageVersion }}
{{- printf .Values.injector.wasm.imageVersion -}}
{{- else -}}
{{- printf .Chart.AppVersion }}
{{- end }}
{{- end -}}

{{/*
Injectee nginx ingress controller init image version. Allows an option for one to specify a different version
other than the app version in the chart. Otherwise, it's just Chart.AppVersion
*/}}
{{- define "injecteeNginxImageVersion" -}}
{{- if .Values.injector.nginx.imageVersion }}
{{- printf .Values.injector.nginx.imageVersion -}}
{{- else -}}
{{- printf .Chart.AppVersion }}
{{- end }}
{{- end -}}

{{/*
Image registry
- If we are not creating k8s manifest, image registry is registry/registrySuffix. Otherwise, it's just registrySuffix.
*/}}
{{- define "imageRegistry" -}}
{{- $registry := .Values.imageCredentials.registry }}
{{- $registrySuffix := .Values.imageCredentials.registrySuffix }}
{{- if not .Values.k8sManifests }}
{{- if eq $registrySuffix "" }}
{{- printf "%s" $registry }}
{{- else }}
{{- printf "%s/%s" $registry $registrySuffix }}
{{- end }}
{{- else }}
{{- printf "%s" $registrySuffix }}
{{- end }}
{{- end -}}

{{/*
Injectee reporting endpoint based on the traceReporterType and tlsEnabled
The endpoint should be in the formart <host>:<port>
*/}}
{{- define "injecteeReportingEndpoint" -}}
{{- if .Values.injector.reportingEndpoint }}
{{- printf "%s" .Values.injector.reportingEndpoint }}
{{- else if .Values.tlsEnabled }}
{{- printf "agent.%s:%d" .Release.Namespace (int .Values.tlsServerPort) }}
{{- else }}
{{- if and (eq .Values.injector.traceReporterType "OTLP") (.Values.collector.receivers.otlp.enabled) }}
{{- if .Values.httpReverseProxyEnabled }}
{{- printf "agent.%s:%d" .Release.Namespace (int .Values.restServerPort) }}
{{- else }}
{{- printf "agent.%s:%d" .Release.Namespace (int .Values.collector.ports.opentelemetry) }}
{{- end }}
{{- else if and (eq .Values.injector.traceReporterType "ZIPKIN") (.Values.collector.receivers.zipkin.enabled) }}
{{- if .Values.httpReverseProxyEnabled }}
{{- printf "agent.%s:%d" .Release.Namespace (int .Values.restServerPort) }}
{{- else }}
{{- printf "agent.%s:%d" .Release.Namespace (int .Values.collector.ports.zipkin) }}
{{- end }}
{{- else }}
{{- fail "Invalid .Values.injector.traceReporterType. Only OTLP or ZIPKIN allowed. If .Values.httpReverseProxyEnabled, .Values.restServerPort will be the port. Otherwise, corresponding value .Values.collector.receivers.otlp.enabled or .Values.collector.receivers.zipkin.enabled should be true" }}
{{- end }}
{{- end }}
{{- end -}}

{{/*
Injectee remote config endpoint based on tlsEnabled
*/}}
{{- define "injecteeRemoteConfigEndpoint" -}}
{{- if .Values.injector.reportingEndpoint }}
{{- printf "%s" .Values.injector.reportingEndpoint }}
{{- else if .Values.tlsEnabled }}
{{- printf "agent.%s:%d" .Release.Namespace (int .Values.tlsServerPort) }}
{{- else if .Values.httpReverseProxyEnabled }}
{{- printf "agent.%s:%d" .Release.Namespace (int .Values.restServerPort) }}
{{- else }}
{{- printf "agent.%s:%d" .Release.Namespace (int .Values.serverPort) }}
{{- end }}
{{- end -}}

{{/*
Injectee reporting port based on reverseProxyEnabled for nginx cpp module
*/}}
{{- define "injecteeNginxReportingPort" -}}
{{- if .Values.tlsEnabled }}
{{- printf "%d" (int .Values.tlsServerPort) }}
{{- else if .Values.httpReverseProxyEnabled }}
{{- printf "%d" (int .Values.restServerPort) }}
{{- else }}
{{- printf "%d" (int .Values.collector.ports.zipkin) }}
{{- end }}
{{- end -}}


{{/*
useAdmissionRegBeta returns "true" if the k8s minor version is "15" and below
and false otherwise. This is based on the k8s api docs: at least as new as v1.16 (to use admissionregistration.k8s.io/v1),
or v1.9 (to use admissionregistration.k8s.io/v1beta1).
When fetching k8s minor version remove the non digit characters incase of such envs as GKE and EKS which return
versions like "19+".
*/}}
{{- define "useBetaAdmissionReg" -}}
{{- if lt ( int ( regexReplaceAll "\\D+" .Capabilities.KubeVersion.Minor "" ) ) 16 }}
{{- printf "true" -}}
{{- else -}}
{{- printf "false"}}
{{- end }}
{{- end -}}

{{/*
tlsServerPort will be set to 443 automatically if we are deploying in k8s v1.16 and below
and hence using admissionregistration.k8s.io/v1beta1.
Don't use 443 on old clusters if daemonSetMirroringEnabled as hostNetworking is enabled
and we can have port collisions as 443 is commonly used such as with contour.
When fetching k8s minor version remove the non digit characters incase of such envs as GKE and EKS which return
versions like "19+".
*/}}
{{- define "tlsServerPort" -}}
{{- if and (lt ( int ( regexReplaceAll "\\D+" .Capabilities.KubeVersion.Minor "" ) ) 16) (eq (include "daemonSetMirroringEnabled" .) "false") }}
{{- printf "443" -}}
{{- else -}}
{{- printf "%s" ( .Values.tlsServerPort | toString ) }}
{{- end }}
{{- end -}}

{{- define "podMirroringEnabled" -}}
{{- if and (eq .Values.podMirroringEnabled true) (eq .Values.injectorEnabled true) }}
{{- true }}
{{- else }}
{{- false }}
{{- end }}
{{- end -}}

{{/*
DaemonSetMirroring enabled
- If .Values.runAsDaemonSet and .Values.daemonSetMirroring is available
--- return .Values.daemonSetMirroring.enabled
- else
--- return false
*/}}
{{- define "daemonSetMirroringEnabled" -}}
{{- if and (eq .Values.runAsDaemonSet true) (eq .Values.daemonSetMirroringEnabled true) }}
{{- true }}
{{- else }}
{{- false }}
{{- end }}
{{- end -}}

{{- define "mirroringEnabled" -}}
{{- if or (eq (include "daemonSetMirroringEnabled" .) "true") (eq (include "podMirroringEnabled" .) "true") }}
{{- true }}
{{- else }}
{{- false }}
{{- end }}
{{- end -}}

{{- define "mirroringBpfFilter" -}}
{{- if eq (include "daemonSetMirroringEnabled" .) "true" }}
{{- print "not net 127.0.0.0/8" -}}
{{- else }}
{{- print "not net 127.0.0.0/8 and port 4789" -}}
{{- end }}
{{- end -}}

{{/*
DaemonSetMirrorAll
- If DaemonSetMirroring enabled and .Values.daemonSetMirrorAllNamespaces is set
--- return true
- else
--- return false
*/}}
{{- define "daemonSetMirrorAllNamespaces" -}}
{{- if and (eq (include "daemonSetMirroringEnabled" .) "true") (eq .Values.daemonSetMirrorAllNamespaces true) }}
{{- true }}
{{- else }}
{{- false }}
{{- end }}
{{- end -}}

{{/*
Blocking enabled
- If .Values.blockingEnabled and daemonset mirroring is off
--- return true
- else
--- return false
*/}}
{{- define "blockingEnabled" -}}
{{- if and (eq .Values.blockingEnabled true) (eq (include "daemonSetMirroringEnabled" .) "false") }}
{{- true }}
{{- else }}
{{- false }}
{{- end }}
{{- end -}}

{{/*
Remote TLS ca cert file name
*/}}
{{- define "RemoteTlsCaCertFileName" -}}
{{- if .Values.remoteCaBundle }}
{{- print "/conf/remote/certs/ca_cert.crt" }}
{{- else if and .Values.remoteCaCertSecret.secretName .Values.remoteCaCertSecret.caCertFileName }}
{{- printf "/conf/remote/certs/%s" .Values.remoteCaCertSecret.caCertFileName }}
{{- else if .Values.remoteCaCertFile }}
{{- print .Values.remoteCaCertFile }}
{{- else }}
{{- print "" }}
{{- end }}
{{- end -}}

{{/*
Add Remote TLS ca cert volumes to container.
- True if remoteCaBundle or remoteCaCertSecret is set.
- False for all other scenarios including when remoteCaCertFile is set.
*/}}
{{- define "addRemoteTlsCaCertVolume" -}}
{{- if or .Values.remoteCaBundle (and .Values.remoteCaCertSecret.secretName .Values.remoteCaCertSecret.caCertFileName) }}
{{- print "true" }}
{{- else }}
{{- print "false" }}
{{- end }}
{{- end -}}

{{/*
Remote TLS CA cert secret name. Only valid when remoteCaBundle or remoteCaCertSecret is set.
*/}}
{{- define "remoteTlsCaCertSecretName" -}}
{{- if .Values.remoteCaBundle }}
{{- printf "%s-remote-ca-cert" .Chart.Name }}
{{- else }}
{{- print .Values.remoteCaCertSecret.secretName }}
{{- end }}
{{- end -}}

{{/*
ebpf remote endpoint based on tlsEnabled
The endpoint should be in the format <host>:<port>
*/}}
{{- define "ebpfRemoteEndpoint" -}}
{{- if .Values.ebpfOnly }}
{{- printf "%s" .Values.ebpfRemoteEndpoint }}
{{- else if .Values.tlsEnabled }}
{{- printf "agent.%s:%d" .Release.Namespace (int .Values.tlsServerPort) }}
{{- else if .Values.httpReverseProxyEnabled }}
{{- printf "agent.%s:%d" .Release.Namespace (int .Values.restServerPort) }}
{{- else }}
{{- printf "agent.%s:%d" .Release.Namespace (int .Values.serverPort) }}
{{- end }}
{{- end -}}

{{/*
ebpf reporting endpoint based on tlsEnabled
The endpoint should be in the formart <host>:<port>
*/}}
{{- define "ebpfReportingEndpoint" -}}
{{- if .Values.ebpfOnly }}
{{- printf "%s" .Values.ebpfReportingEndpoint}}
{{- else if .Values.tlsEnabled }}
{{- if and (eq .Values.ebpfTraceReporterType "OTLP") (.Values.collector.receivers.otlp.enabled) }}
{{- printf "agent.%s:%d" .Release.Namespace (int .Values.tlsServerPort) }}
{{- else if and (eq .Values.ebpfTraceReporterType "ZIPKIN") (.Values.collector.receivers.zipkin.enabled) }}
{{- printf "https://agent.%s:%d/api/v2/spans" .Release.Namespace (int .Values.tlsServerPort) }}
{{- else }}
{{- fail "Value ebpfTraceReporterType is invalid. Allowed values are OTLP and ZIPKIN. Corresponding value collector.receivers.otlp.enabled or collector.receivers.zipkin.enabled should also be true." }}
{{- end }}
{{- else if .Values.httpReverseProxyEnabled }}
{{- if and (eq .Values.ebpfTraceReporterType "OTLP") (.Values.collector.receivers.otlp.enabled) }}
{{- printf "agent.%s:%d" .Release.Namespace (int .Values.restServerPort) }}
{{- else if and (eq .Values.ebpfTraceReporterType "ZIPKIN") (.Values.collector.receivers.zipkin.enabled) }}
{{- printf "https://agent.%s:%d/api/v2/spans" .Release.Namespace (int .Values.restServerPort) }}
{{- else }}
{{- fail "Value ebpfTraceReporterType is invalid. Allowed values are OTLP and ZIPKIN. Corresponding value collector.receivers.otlp.enabled or collector.receivers.zipkin.enabled should also be true." }}
{{- end }}
{{- else }}
{{- if and (eq .Values.ebpfTraceReporterType "OTLP") (.Values.collector.receivers.otlp.enabled) }}
{{- printf "agent.%s:%d" .Release.Namespace (int .Values.collector.ports.opentelemetry) }}
{{- else if and (eq .Values.ebpfTraceReporterType "ZIPKIN") (.Values.collector.receivers.zipkin.enabled) }}
{{- printf "http://agent.%s:%d/api/v2/spans" .Release.Namespace (int .Values.collector.ports.zipkin) }}
{{- else }}
{{- fail "Value ebpfTraceReporterType is invalid. Allowed values are OTLP and ZIPKIN. Corresponding value collector.receivers.otlp.enabled or collector.receivers.zipkin.enabled should also be true." }}
{{- end }}
{{- end }}
{{- end -}}

{{/*
TPA TLS ca cert file name for clients eg. ebpf which can report to a TPA in the same cluster or a different TPA in a different cluster.
*/}}
{{- define "tpaTlsCaCertForClientsFileName" -}}
{{- if not .Values.ebpfOnly }}
{{- print (include "tlsRootCaCertFileName" .) }}
{{- else }}
{{- if .Values.tpaCaBundle }}
{{- print "/conf/certs/ca_cert.crt" }}
{{- else if and .Values.tpaCaCertSecret.secretName .Values.tpaCaCertSecret.caCertFileName }}
{{- printf "/conf/certs/%s" .Values.tpaCaCertSecret.caCertFileName }}
{{- else if .Values.tpaCaCertFile }}
{{- print .Values.tpaCaCertFile }}
{{- else }}
{{- print "" }}
{{- end }}
{{- end }}
{{- end -}}

{{/*
Add TPA TLS ca cert for clients volumes to container.
- True if tpaCaBundle or tpaCaCertSecret is set.
- False for all other scenarios including when tpaCaCertFile is set.
*/}}
{{- define "addTpaTlsCaCertForClientsVolume" -}}
{{- if not .Values.ebpfOnly }}
{{- if and (eq .Values.tlsEnabled true) (eq (include "addTlsCertVolume" .) "true") }}
{{- print "true" }}
{{- else }}
{{- print "false" }}
{{- end }}
{{- else }}
{{- if or .Values.tpaCaBundle (and .Values.tpaCaCertSecret.secretName .Values.tpaCaCertSecret.caCertFileName) }}
{{- print "true" }}
{{- else }}
{{- print "false" }}
{{- end }}
{{- end }}
{{- end -}}

{{/*
TPA TLS CA cert for clients secret name. Only valid when tpaCaBundle or tpaCaCertSecret is set.
*/}}
{{- define "tpaTlsCaCertForClientsSecretName" -}}
{{- if not .Values.ebpfOnly }}
{{- print (include "tlsCertsSecretName" .) }}
{{- else }}
{{- if .Values.tpaCaBundle }}
{{- printf "%s-tpa-ca-cert" .Chart.Name }}
{{- else }}
{{- print .Values.tpaCaCertSecret.secretName }}
{{- end }}
{{- end }}
{{- end -}}

{{/*
Ebpf tls enabled. Whether the tracer should reach out to TPA on tls.
*/}}
{{- define "ebpfToTpaTlsEnabled" -}}
{{- if not .Values.ebpfOnly }}
{{- .Values.tlsEnabled }}
{{- else }}
{{- .Values.ebpfToTpaTlsEnabled }}
{{- end }}
{{- end -}}

{{/*
traceable_traces_buffer processor noOfWorkers
When .Values.tracesBufferingProcessor.noOfWorkers is set to 0 it will default to max(2, resources.cpu.limit).
Set it to non-zero to override. It is recommended that it is >= 2.
*/}}
{{- define "tracesBufferingNoOfWorkers" -}}
{{- if eq (int .Values.tracesBufferingProcessor.noOfWorkers) 0 }}
{{- if hasSuffix "m" (toString .Values.resources.limits.cpu) }}
{{- max 2 (int (floor (div (trimSuffix "m" .Values.resources.limits.cpu) 1000))) }}
{{- else }}
{{- max 2 (int (floor .Values.resources.limits.cpu)) }}
{{- end }}
{{- else }}
{{- int .Values.tracesBufferingProcessor.noOfWorkers }}
{{- end }}
{{- end -}}


{{/*
tpaImageSeparator
When .Values.imageVersion is prefixed with sha256, image name and version needs to be separated with a @ instead of :
*/}}
{{- define "tpaImageSeparator" -}}
{{- if hasPrefix "sha256:" .Values.imageVersion }}
{{- print "@" }}
{{- else }}
{{- print ":" }}
{{- end }}
{{- end -}}

{{/*
ebpfImageSeparator
When .Values.ebpfTracerVersion is prefixed with sha256:, image name and version needs to be separated with a @ instead of :
*/}}
{{- define "ebpfImageSeparator" -}}
{{- if hasPrefix "sha256:" .Values.ebpfTracerVersion }}
{{- print "@" }}
{{- else }}
{{- print ":" }}
{{- end }}
{{- end -}}

{{/*
surricataImageSeparator
When .Values.suricataVersion is prefixed with sha256:, image name and version needs to be separated with a @ instead of :
*/}}
{{- define "suricataImageSeparator" -}}
{{- if hasPrefix "sha256:" .Values.suricataVersion }}
{{- print "@" }}
{{- else }}
{{- print ":" }}
{{- end }}
{{- end -}}

{{/*
extensionServiceImageSeparator
When .Values.imageVersion is prefixed with sha256, image name and version needs to be separated with a @ instead of :
*/}}
{{- define "extensionServiceImageSeparator" -}}
{{- if hasPrefix "sha256:" .Values.extensionService.imageVersion }}
{{- print "@" }}
{{- else }}
{{- print ":" }}
{{- end }}
{{- end -}}

{{/*
telemetryReportingEndpoint
When .Values.telemetryReportingEndpoint is set use that, otherwise use the opentelemetry collector grpc port
*/}}
{{- define "telemetryReportingEndpoint" -}}
{{- if .Values.telemetryReportingEndpoint }}
{{- print .Values.telemetryReportingEndpoint }}
{{- else  }}
{{- printf "localhost:%d" (int .Values.collector.ports.opentelemetry)}}
{{- end }}
{{- end -}}

{{/*
ebpfLogLevel
When .Values.ebpfLogging.level is set use that, otherwise use ebpfLogLevel.
*/}}
{{- define "ebpfLogLevel" -}}
{{- if .Values.ebpfLogging.level }}
{{- print .Values.ebpfLogging.level }}
{{- else  }}
{{- print .Values.ebpfLogLevel }}
{{- end }}
{{- end -}}

{{/*
Injector Webhook service host name.
This is necessary since the k8s apiserver needs a ClusterIP service which is set to None when serviceType=Headless.
So we would need another service when serviceType=Headless and injectorEnabled=true. This returns the hostname of the
service based on those conditions and will be used in the MutatingWebhookConfig
- If serviceType=Headless and injectorEnabled=true, the host name is "agent-injector". Otherwise, it is "agent"
*/}}
{{- define "injectorServiceHostName" -}}
{{- if and (.Values.injectorEnabled) (eq .Values.serviceType "Headless") }}
{{- print "agent-injector" }}
{{- else }}
{{- print "agent" }}
{{- end }}
{{- end -}}

{{- define "ebpfGoMemLimit" -}}
{{- if eq .Values.ebpfEnableGoMemoryLimit true }}
{{- print .Values.daemonSetMirroring.resources.limits.memory }}
{{- else  }}
{{- print "0" }}
{{- end }}
{{- end -}}

{{- define "tpaContainerSecurityContextUser" -}}
{{- if .Values.securityContext }}
{{- if .Values.securityContext.runAsUser }}
{{- print .Values.securityContext.runAsUser }}
{{- else }}
{{- print "0" }}
{{- end }}
{{- else }}
{{- print "0" }}
{{- end }}
{{- end -}}
