{{/*
ebpf daemonset template. Used in deployment.
*/}}
{{- define "ebpfContainerTemplate" -}}
{{- $top := index . 0 -}}
{{- $restartUuid := index . 1 "restartUuid" -}}
{{- $regcredSecretName := include "regcredSecretName" $top }}
{{- $tlsServerPort := include "tlsServerPort" $top }}
{{- $addRemoteTlsCaCertVolume := include "addRemoteTlsCaCertVolume" $top }}
{{- $addClientTlsCertKeyVolume := include "mtlsHelper.AddClientTlsCertKeyVolume" $top }}
{{- $remoteTlsCaCertSecretName := include "remoteTlsCaCertSecretName" $top }}
{{- $clientTlsCertKeySecretName := include "mtlsHelper.ClientTlsCertKeySecretName" $top }}
{{- $additionalAnnotations := include "traceableai.additionalAnnotations" $top }}
{{- $registry :=  include "imageRegistry" $top }}
{{- $ebpfSeparator := include "ebpfImageSeparator" $top }}
{{- $addTpaTlsCaCertForClientsVolume := include "addTpaTlsCaCertForClientsVolume" $top }}
{{- $tpaTlsCaCertForClientsSecretName := include "tpaTlsCaCertForClientsSecretName" $top }}
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: traceable-ebpf-tracer-ds
  namespace: {{ $top.Release.Namespace }}
  labels:
{{ include "traceableai.labels" $top | indent 4 }}
spec:
{{- if $top.Values.ebpfUpdateStrategy.enabled }}
  updateStrategy:
    type: {{ $top.Values.ebpfUpdateStrategy.type }}
{{- if eq $top.Values.ebpfUpdateStrategy.type "RollingUpdate" }}
    rollingUpdate:
      maxSurge: {{ $top.Values.ebpfUpdateStrategy.rollingUpdate.maxSurge }}
      maxUnavailable: {{ $top.Values.ebpfUpdateStrategy.rollingUpdate.maxUnavailable }}
{{- end }}
{{- end }}
  selector:
    matchLabels:
      app.kubernetes.io/name: {{ $top.Chart.Name }}-ebpf
      app.kubernetes.io/instance: {{ $top.Release.Name }}-ebpf
  template:
    metadata:
      labels:
        app.kubernetes.io/name: {{ $top.Chart.Name }}-ebpf
        app.kubernetes.io/instance: {{ $top.Release.Name }}-ebpf
        app.kubernetes.io/component: traceable-agent
        {{- include "traceableai.only.global.labels" $top | nindent 8 }}
      annotations:
        checksum/config: {{ include (print $top.Template.BasePath "/ebpf-configmap.yaml") $top | sha256sum }}
{{- if and (eq (include "addTlsCerts" $top) "true") (eq (include "tlsCertsMode" $top) "self_gen") }}
        restart-trigger-uuid: {{ $restartUuid }}
{{- end }}
        {{- $additionalAnnotations | nindent 8 }}
        {{- include "traceableai.annotations" $top | nindent 8 }}
    spec:
{{- with $top.Values.ebpfNodeSelectors }}
      nodeSelector:
{{- toYaml . | nindent 8 }}
{{- end }}
      affinity:
        nodeAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            nodeSelectorTerms:
{{- range $top.Values.ebpfNodeAffinityMatchExpressions }}
            - matchExpressions:
              - key: kubernetes.io/os
                operator: Exists
              - key: kubernetes.io/os
                operator: In
                values:
                - linux
{{- if not $top.Values.ebpfDeployOnMaster }}
              - key: node-role.kubernetes.io/control-plane
                operator: DoesNotExist
{{- if lt ( int ( regexReplaceAll "\\D+" $top.Capabilities.KubeVersion.Minor "" ) ) 20 }}
              - key: node-role.kubernetes.io/master
                operator: DoesNotExist
{{- end }}
{{- end }}
{{- if gt (len .matchExpressions) 0 -}}
{{- toYaml .matchExpressions | nindent 14 }}
{{- end }}
{{- if lt ( int ( regexReplaceAll "\\D+" $top.Capabilities.KubeVersion.Minor "" ) ) 14 }}
            - matchExpressions:
              - key: beta.kubernetes.io/os
                operator: Exists
              - key: beta.kubernetes.io/os
                operator: In
                values:
                - linux
{{- if not $top.Values.ebpfDeployOnMaster }}
              - key: node-role.kubernetes.io/control-plane
                operator: DoesNotExist
              - key: node-role.kubernetes.io/master
                operator: DoesNotExist
{{- end }}
{{- if gt (len .matchExpressions) 0 -}}
{{- toYaml .matchExpressions | nindent 14 }}
{{- end }}
{{- end }}
{{- end }}
{{- if ne $regcredSecretName "" }}
      imagePullSecrets:
        - name: {{ $regcredSecretName }}
{{- end }}
      serviceAccountName: {{ $top.Values.ebpfServiceAccountName }}
      hostPID: {{ or $top.Values.ebpfEnableJavaTlsCapture (gt (len $top.Values.ebpfSslKeylogIncludeRules) 0) }}
{{- if $top.Values.ebpfPriorityClass.enabled }}
      priorityClassName: {{ $top.Values.ebpfPriorityClass.name }}
{{- end }}
      containers:
        - name: traceable-ebpf-tracer
          image: "{{ $registry }}/{{ $top.Values.ebpfTracerImageName }}{{ $ebpfSeparator }}{{ $top.Values.ebpfTracerVersion }}"
          imagePullPolicy: {{ $top.Values.imagePullPolicy }}
          args: ["-f", "/conf/ebpfconfig.yaml"]
          env:
            - name: NODE_NAME
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName
            - name: NODE_IP
              valueFrom:
                fieldRef:
                  fieldPath: status.hostIP
{{- range $top.Values.ebpfEnvironmentVariables }}
            - name: {{ .name }}
              value: {{ .value }}
{{- end }}
          volumeMounts:
{{- if and (not $top.Values.ebpfEnableJavaTlsCapture) (eq (len $top.Values.ebpfSslKeylogIncludeRules) 0) }}
            - name: {{ $top.Chart.Name }}-proc-volume
              mountPath: /hostproc
              readOnly: true
{{- end }}
            - name: {{ $top.Chart.Name }}-ebpf-config-map-volume
              mountPath: /conf
            - name: {{ $top.Chart.Name }}-sys-volume
              mountPath: /sys
{{- if (eq $addTpaTlsCaCertForClientsVolume "true" ) }}
            - name: {{ $top.Chart.Name }}-cert-volume
              mountPath: /conf/certs
              readOnly: true
{{- end }}
{{- if eq $addClientTlsCertKeyVolume "true" }}
          - name: {{ $top.Chart.Name }}-remote-client-cert-key-volume
            mountPath: /conf/remote/client-certs
            readOnly: true
{{- end }}
{{- if $top.Values.ebpfBtfDownloadsPath }}
            - name: ebpf-btf-volume
              mountPath: {{ $top.Values.ebpfBtfDownloadsPath }}
{{- end }}
          resources:
            {{- toYaml $top.Values.daemonSetMirroring.resources | nindent 12 }}
{{- if not $top.Values.useCustomSecurityContext }}
          securityContext:
            runAsUser: 0
{{- if $top.Values.ebpfRunAsPrivileged }}
            privileged: true
{{- end }}
            readOnlyRootFilesystem: true
            capabilities:
              add:
{{- toYaml $top.Values.ebpfAllowedCapabilities | nindent 14 }}
{{- if $top.Values.ebpfSELinuxOptionsEnabled }}
            seLinuxOptions:
              role: {{ $top.Values.ebpfSELinuxOptionsRole }}
              type: {{ $top.Values.ebpfSELinuxOptionsType }}
              user: {{ $top.Values.ebpfSELinuxOptionsUser }}
{{- end }}
{{- else if or $top.Values.ebpfSecurityContext $top.Values.commonContainerSecurityContext }}
          securityContext:
{{- if $top.Values.ebpfSecurityContext }}
{{- toYaml $top.Values.ebpfSecurityContext | nindent 12 }}
{{- else }}
{{- toYaml $top.Values.commonContainerSecurityContext | nindent 12 }}
{{- end }}
{{- end }}
      volumes:
        - name: {{ $top.Chart.Name }}-ebpf-config-map-volume
          configMap:
            name: {{ $top.Chart.Name }}-ebpf-config-map
{{- if (eq $addTpaTlsCaCertForClientsVolume "true" ) }}
        - name: {{ $top.Chart.Name }}-cert-volume
          secret:
            secretName: {{ $tpaTlsCaCertForClientsSecretName }}
{{- end }}
{{- if and (not $top.Values.ebpfEnableJavaTlsCapture) (eq (len $top.Values.ebpfSslKeylogIncludeRules) 0) }}
        - name: {{ $top.Chart.Name }}-proc-volume
          hostPath:
            path: /proc
{{- end }}
        - name: {{ $top.Chart.Name }}-sys-volume
          hostPath:
            path: /sys
{{- if $top.Values.ebpfBtfDownloadsPath }}
        - name: ebpf-btf-volume
          emptyDir:
            sizeLimit: 64Mi
{{- end }}

{{- if $top.Values.ebpfTolerations }}
      tolerations:
        {{- toYaml $top.Values.ebpfTolerations | nindent 8 }}
{{- end }}
---
{{- end -}}
