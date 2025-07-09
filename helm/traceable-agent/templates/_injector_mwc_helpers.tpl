{{/*
Traceable agent injector mutating webhook config template. Used in both daemonset and deployment.
*/}}
{{- define "mutatingWebhookConfigTemplate" -}}
{{- $top := index . 0 -}}
{{- $caBundle := index . 1 "caBundle" -}}
{{- $useBetaAdmissionReg := include "useBetaAdmissionReg" $top }}
{{- $tlsServerPort := int ( include "tlsServerPort" $top ) }}
{{- $injectorServiceHostName := include "injectorServiceHostName" $top }}
{{- if eq  $useBetaAdmissionReg "true" }}
apiVersion: admissionregistration.k8s.io/v1beta1
{{- else }}
apiVersion: admissionregistration.k8s.io/v1
{{- end }}
kind: MutatingWebhookConfiguration
metadata:
  name: {{ $top.Chart.Name }}-injector-{{ $top.Release.Namespace }}
  namespace: {{ $top.Release.Namespace }}
  labels:
{{ include "traceableai.labels" $top | indent 4 }}
  annotations:
{{ include "traceableai.annotations" $top | indent 4 }}
webhooks:
  - name: "java-injector.{{ $top.Release.Namespace }}.svc"
{{- if eq $useBetaAdmissionReg "true" }}
    admissionReviewVersions: ["v1beta1"]
{{- else }}
    admissionReviewVersions: ["v1", "v1beta1"]
{{- end }}
    sideEffects: None
    clientConfig:
{{- if eq $top.Values.injectorWebhookDomain "" }}
      service:
        name: {{ $injectorServiceHostName }}
        namespace: {{ $top.Release.Namespace }}
        path: /injector/v1/inject-java
{{- if ne $useBetaAdmissionReg "true" }}
        port: {{ $tlsServerPort }}
{{- end }}
{{- else }}
      url: https://{{ $top.Values.injectorWebhookDomain }}/injector/v1/inject-java
{{- end }}
{{- if ne $caBundle "" }}
      caBundle: {{ $caBundle }}
{{- end }}

    rules:
      - operations: [ "CREATE" ]
        apiGroups: [""]
        apiVersions: ["v1"]
        resources: ["pods"]
    failurePolicy: {{ $top.Values.injector.failurePolicy }}
{{- if not $top.Values.injector.java.matchSelectors }}
    namespaceSelector:
      matchLabels:
        traceableai-inject-java: enabled
{{- end }}

  - name: "tme-injector.{{ $top.Release.Namespace }}.svc"
{{- if eq $useBetaAdmissionReg "true" }}
    admissionReviewVersions: ["v1beta1"]
{{- else }}
    admissionReviewVersions: ["v1", "v1beta1"]
{{- end }}
    sideEffects: None
    clientConfig:
{{- if eq $top.Values.injectorWebhookDomain "" }}
      service:
        name: {{ $injectorServiceHostName }}
        namespace: {{ $top.Release.Namespace }}
        path: /injector/v1/inject-tme
{{- if ne $useBetaAdmissionReg "true" }}
        port: {{ $tlsServerPort }}
{{- end }}
{{- else }}
      url: https://{{ $top.Values.injectorWebhookDomain }}/injector/v1/inject-tme
{{- end }}
{{- if ne $caBundle "" }}
      caBundle: {{ $caBundle }}
{{- end }}

    rules:
      - operations: [ "CREATE" ]
        apiGroups: [""]
        apiVersions: ["v1"]
        resources: ["pods"]
    failurePolicy: {{ $top.Values.injector.failurePolicy }}
{{- if and ( not $top.Values.injector.tme.matchSelectors ) ( not $top.Values.injector.nginx.matchSelectors ) ( not $top.Values.injector.haproxy.matchSelectors ) }}
    namespaceSelector:
      matchLabels:
        traceableai-inject-tme: enabled
{{- end }}

  - name: "nginx-cpp-injector.{{ $top.Release.Namespace }}.svc"
{{- if eq $useBetaAdmissionReg "true" }}
    admissionReviewVersions: ["v1beta1"]
{{- else }}
    admissionReviewVersions: ["v1", "v1beta1"]
{{- end }}
    sideEffects: None
    clientConfig:
{{- if eq $top.Values.injectorWebhookDomain "" }}
      service:
        name: {{ $injectorServiceHostName }}
        namespace: {{ $top.Release.Namespace }}
        path: /injector/v1/inject-nginx-cpp
{{- if ne $useBetaAdmissionReg "true" }}
        port: {{ $tlsServerPort }}
{{- end }}
{{- else }}
      url: https://{{ $top.Values.injectorWebhookDomain }}/injector/v1/inject-nginx-cpp
{{- end }}
{{- if ne $caBundle "" }}
      caBundle: {{ $caBundle }}
{{- end }}

    rules:
      - operations: [ "CREATE" ]
        apiGroups: [""]
        apiVersions: ["v1"]
        resources: ["pods"]
    failurePolicy: {{ $top.Values.injector.failurePolicy }}
{{- if not $top.Values.injector.nginxCpp.matchSelectors}}
    namespaceSelector:
      matchLabels:
        traceableai-inject-nginx-cpp: enabled
{{- end }}

  - name: "extension-injector.{{ $top.Release.Namespace }}.svc"
{{- if eq $useBetaAdmissionReg "true" }}
    admissionReviewVersions: ["v1beta1"]
{{- else }}
    admissionReviewVersions: ["v1", "v1beta1"]
{{- end }}
    sideEffects: None
    clientConfig:
{{- if eq $top.Values.injectorWebhookDomain "" }}
      service:
        name: {{ $injectorServiceHostName }}
        namespace: {{ $top.Release.Namespace }}
        path: /injector/v1/inject-extension
{{- if ne $useBetaAdmissionReg "true" }}
        port: {{ $tlsServerPort }}
{{- end }}
{{- else }}
      url: https://{{ $top.Values.injectorWebhookDomain }}/injector/v1/inject-extension
{{- end }}
{{- if ne $caBundle "" }}
      caBundle: {{ $caBundle }}
{{- end }}

    rules:
      - operations: [ "CREATE" ]
        apiGroups: [""]
        apiVersions: ["v1"]
        resources: ["pods"]
    failurePolicy: {{ $top.Values.injector.failurePolicy }}
{{- if not $top.Values.extensionService.matchSelectors}}
    namespaceSelector:
      matchLabels:
        traceableai-inject-extension: enabled
{{- end }}
  - name: "mirror-injector.traceableai.svc"
{{- if eq $useBetaAdmissionReg "true" }}
    admissionReviewVersions: ["v1beta1"]
{{- else }}
    admissionReviewVersions: ["v1", "v1beta1"]
{{- end }}
    sideEffects: None
    clientConfig:
{{- if eq $top.Values.injectorWebhookDomain "" }}
      service:
        name: {{ $injectorServiceHostName }}
        namespace: {{ $top.Release.Namespace }}
        path: /injector/v1/inject-mirror
{{- if ne $useBetaAdmissionReg "true" }}
        port: {{ $tlsServerPort }}
{{- end }}
{{- else }}
      url: https://{{ $top.Values.injectorWebhookDomain }}/injector/v1/inject-mirror
{{- end }}
{{- if ne $caBundle "" }}
      caBundle: {{ $caBundle }}
{{- end }}

    rules:
      - operations: [ "CREATE" ]
        apiGroups: [""]
        apiVersions: ["v1"]
        resources: ["pods"]
    failurePolicy: {{ $top.Values.injector.failurePolicy }}
{{- if not $top.Values.injector.mirror.matchSelectors }}
    namespaceSelector:
      matchLabels:
        traceableai-inject-mirror: enabled
{{- end }}

  # Backwards compatibility webhooks. Using the old/deprecated namespaceSelector matchLabels.
  - name: "java-injector-deprecated.{{ $top.Release.Namespace }}.svc"
{{- if eq $useBetaAdmissionReg "true" }}
    admissionReviewVersions: ["v1beta1"]
{{- else }}
    admissionReviewVersions: ["v1", "v1beta1"]
{{- end }}
    sideEffects: None
    clientConfig:
{{- if eq $top.Values.injectorWebhookDomain "" }}
      service:
        name: {{ $injectorServiceHostName }}
        namespace: {{ $top.Release.Namespace }}
        path: /injector/v1/inject-java
{{- if ne $useBetaAdmissionReg "true" }}
        port: {{ $tlsServerPort }}
{{- end }}
{{- else }}
      url: https://{{ $top.Values.injectorWebhookDomain }}/injector/v1/inject-java
{{- end }}
{{- if ne $caBundle "" }}
      caBundle: {{ $caBundle }}
{{- end }}

    rules:
      - operations: [ "CREATE" ]
        apiGroups: [""]
        apiVersions: ["v1"]
        resources: ["pods"]
    failurePolicy: {{ $top.Values.injector.failurePolicy }}
    namespaceSelector:
      matchLabels:
        traceableai-instrumentation: enabled
  - name: "tme-injector-deprecated.{{ $top.Release.Namespace }}.svc"
{{- if eq $useBetaAdmissionReg "true" }}
    admissionReviewVersions: ["v1beta1"]
{{- else }}
    admissionReviewVersions: ["v1", "v1beta1"]
{{- end }}
    sideEffects: None
    clientConfig:
{{- if eq $top.Values.injectorWebhookDomain "" }}
      service:
        name: {{ $injectorServiceHostName }}
        namespace: {{ $top.Release.Namespace }}
        path: /injector/v1/inject-tme
{{- if ne $useBetaAdmissionReg "true" }}
        port: {{ $tlsServerPort }}
{{- end }}
{{- else }}
      url: https://{{ $top.Values.injectorWebhookDomain }}/injector/v1/inject-tme
{{- end }}
{{- if ne $caBundle "" }}
      caBundle: {{ $caBundle }}
{{- end }}

    rules:
      - operations: [ "CREATE" ]
        apiGroups: [""]
        apiVersions: ["v1"]
        resources: ["pods"]
    failurePolicy: {{ $top.Values.injector.failurePolicy }}
    namespaceSelector:
      matchLabels:
        traceableai-instrumentation: enabled
---
{{- end -}}
