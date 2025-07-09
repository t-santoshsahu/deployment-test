{{/*
Traceable agent container template. Used in both daemonset and deployment.
*/}}
{{- define "traceable-agent.containerTemplate" -}}
{{- $top := index . 0 -}}
{{- $restartUuid := index . 1 "restartUuid" -}}
{{- $regcredSecretName := include "regcredSecretName" $top }}
{{- $environment := $top.Values.environment }}
{{- $injectorEnabled := $top.Values.injectorEnabled }}
{{- $addTlsCertsVolume := eq (include "addTlsCertVolume" $top) "true" }}
{{- $tlsCertSecretName := include "tlsCertsSecretName" $top }}
{{- $tlsServerPort := include "tlsServerPort" $top }}
{{- $daemonSetMirroringEnabled := include "daemonSetMirroringEnabled" $top }}
{{- $addRemoteTlsCaCertVolume := include "addRemoteTlsCaCertVolume" $top }}
{{- $addClientTlsCertKeyVolume := include "mtlsHelper.AddClientTlsCertKeyVolume" $top }}
{{- $remoteTlsCaCertSecretName := include "remoteTlsCaCertSecretName" $top }}
{{- $clientTlsCertKeySecretName := include "mtlsHelper.ClientTlsCertKeySecretName" $top }}
{{- $refreshTokenFilePresent := include "refreshTokenFilePresent" $top }}
{{- $bootstrapRefreshTokenFromGcp := include "bootstrapRefreshTokenFromGcp" $top }}
{{- $additionalAnnotations := include "traceableai.additionalAnnotations" $top }}
{{- $registry :=  include "imageRegistry" $top }}
{{- $tpaSeparator := include "tpaImageSeparator" $top }}
{{- $suricataSeparator := include "suricataImageSeparator" $top }}
{{- $extensionServiceImageSeparator := include "extensionServiceImageSeparator" $top }}
{{- $mirroringEnabled := include "mirroringEnabled" $top }}
{{- $podMirroringEnabled := include "podMirroringEnabled" $top }}
{{- $mirroringBpfFilter := include "mirroringBpfFilter" $top }}
selector:
  matchLabels:
    app.kubernetes.io/name: {{ $top.Chart.Name }}
    app.kubernetes.io/instance: {{ $top.Release.Name }}
template:
  metadata:
    labels:
      app.kubernetes.io/component: traceable-agent
      {{- include "traceableai.labels" $top | nindent 6 }}
    annotations:
      checksum/config: {{ include (print $top.Template.BasePath "/configmap.yaml") $top | sha256sum }}
{{- if $top.Values.grpcToHttp.enabled }}
      checksum/grpc-to-http-config: {{ include (print $top.Template.BasePath "/grpc-to-http-configmap.yaml") $top | sha256sum }}
{{- end }}
{{- if and (eq (include "addTlsCerts" $top) "true") (eq (include "tlsCertsMode" $top) "self_gen") }}
      restart-trigger-uuid: {{ $restartUuid }}
{{- end }}
      {{- $additionalAnnotations | nindent 6 }}
      {{- include "traceableai.annotations" $top | nindent 6 }}
  spec:
{{- with $top.Values.nodeSelectors }}
    nodeSelector:
{{- toYaml . | nindent 6 }}
{{- end }}
    affinity:
      nodeAffinity:
        requiredDuringSchedulingIgnoredDuringExecution:
          nodeSelectorTerms:
{{- range $top.Values.nodeAffinityMatchExpressions }}
          - matchExpressions:
            - key: kubernetes.io/os
              operator: Exists
            - key: kubernetes.io/os
              operator: In
              values:
              - linux
{{- if gt (len .matchExpressions) 0 -}}
{{- toYaml .matchExpressions | nindent 12 }}
{{- end }}
{{- if lt ( int ( regexReplaceAll "\\D+" $top.Capabilities.KubeVersion.Minor "" ) ) 14 }}
          - matchExpressions:
            - key: beta.kubernetes.io/os
              operator: Exists
            - key: beta.kubernetes.io/os
              operator: In
              values:
              - linux
{{- if gt (len .matchExpressions) 0 -}}
{{- toYaml .matchExpressions | nindent 12 }}
{{- end }}
{{- end }}
{{- end }}
{{- with $top.Values.podAffinity }}
      podAffinity:
{{- toYaml . | nindent 8 }}
{{- end }}
{{- with $top.Values.podAntiAffinity }}
      podAntiAffinity:
{{- toYaml . | nindent 8 }}
{{- end }}
{{- with $top.Values.topologySpreadConstraints }}
    topologySpreadConstraints:
{{- toYaml . | nindent 6 }}
{{- end }}
{{- if ne $regcredSecretName "" }}
    imagePullSecrets:
      - name: {{ $regcredSecretName }}
{{- end }}
{{- if eq $daemonSetMirroringEnabled "true" }}
    hostNetwork: true
    dnsPolicy: ClusterFirstWithHostNet
{{- end }}
    serviceAccountName: {{ $top.Values.serviceAccountName }}
{{- if $top.Values.priorityClass.enabled }}
    priorityClassName: {{ $top.Values.priorityClass.name }}
{{- end }}
{{- if $top.Values.tpaPodSecurityContext }}
    securityContext:
{{- toYaml $top.Values.tpaPodSecurityContext | nindent 6 }}
{{- end }}
{{- if eq $bootstrapRefreshTokenFromGcp "true" }}
    initContainers:
      - name: secrets-init
        image: traceableai/secrets-init:0.4.9
        args:
          - copy
          - /secrets/
        volumeMounts:
          - mountPath: /secrets/
            name: secrets-init-volume
{{- if and $top.Values.useCustomSecurityContext (or $top.Values.secretsInitSecurityContext $top.Values.commonContainerSecurityContext) }}
        securityContext:
{{- if $top.Values.secretsInitSecurityContext }}
{{- toYaml $top.Values.secretsInitSecurityContext | nindent 10 }}
{{- else }}
{{- toYaml $top.Values.commonContainerSecurityContext | nindent 10 }}
{{- end }}
{{- end }}
{{- end }}
    containers:
      - name: {{ $top.Chart.Name }}
        image: "{{ $registry }}/{{ $top.Values.imageName }}{{$tpaSeparator}}{{ include "tpaImageVersion" $top }}"
        imagePullPolicy: {{ $top.Values.imagePullPolicy }}
        env:
          # If you are using k8s manifests, create this secret before applying the manifests.
          # See docs.traceable.ai for more info.
{{- if eq $bootstrapRefreshTokenFromGcp "true" }}
          - name: TA_REFRESH_TOKEN
            value: gcp:secretmanager:projects/{{ $top.Values.refreshTokenGcpSecretProject }}/secrets/{{ $top.Values.refreshTokenGcpSecretName }}
{{- else if and (eq $refreshTokenFilePresent "false") (eq (include "useExternalTokenSecret" $top) "false") (eq $top.Values.extCapAuth.enabled false) }}
          # Using default token-secret when no external token or refresh token file is specified
          - name: TA_REFRESH_TOKEN
            valueFrom:
              secretKeyRef:
                name: token-secret
                key: token
{{- end }}
          - name: TA_ENVIRONMENT
            value: "{{ $environment }}"
{{- if and ( $top.Values.injectorEnabled) (eq $top.Values.imagePullSecretName "") (ne $regcredSecretName "") }}
          - name: TA_IMAGE_PULL_SECRET
            value: {{ include "traceableai.imagePullSecret" $top }}
{{- end }}
{{- if and ( $top.Values.injectorEnabled) (ne $top.Values.imagePullSecretName "") }}
          - name: TA_IMAGE_PULL_SECRET_NAME
            value: {{ $top.Values.imagePullSecretName }}
{{- end }}
{{- if $top.Values.extCapJavascriptConfig.enabled}}
          - name: TA_EXT_CAP_JAVASCRIPT_CONFIG_ENABLED
            value: "true"
{{- end }}
{{- if ne $top.Values.extCapJavascriptConfig.selfSigningSecret "" }}
          - name: TA_EXT_CAP_JAVASCRIPT_CONFIG_SELF_SIGNING_SECRET
            value: {{ $top.Values.extCapJavascriptConfig.selfSigningSecret }}
{{- end }}
{{- if ne $top.Values.extCapJavascriptConfig.traceableCookieExpiry "" }}
          - name: TA_EXT_CAP_JAVASCRIPT_CONFIG_TRACEABLE_COOKIE_EXPIRY
            value: {{ $top.Values.extCapJavascriptConfig.traceableCookieExpiry }}
{{- end }}
{{- if ne $top.Values.extCapJavascriptConfig.traceableJwtExpiry "" }}
          - name: TA_EXT_CAP_JAVASCRIPT_CONFIG_TRACEABLE_JWT_EXPIRY
            value: {{ $top.Values.extCapJavascriptConfig.traceableJwtExpiry }}
{{- end }}
{{- if ne $top.Values.extCapJavascriptConfig.captchaConfig.accountSecret "" }}
          - name: TA_EXT_CAP_CAPTCHA_CONFIG_ACCOUNT_SECRET
            value: {{ $top.Values.extCapJavascriptConfig.captchaConfig.accountSecret }}
{{- end }}
{{- if ne $top.Values.extCapJavascriptConfig.captchaConfig.verificationEndpoint "" }}
          - name: TA_EXT_CAP_CAPTCHA_CONFIG_VERIFICATION_ENDPOINT
            value: {{ $top.Values.extCapJavascriptConfig.captchaConfig.verificationEndpoint }}
{{- end }}
          - name: CLUSTER_NAME
            value: {{ $top.Values.clusterName }}
          - name: NODE_NAME
            valueFrom:
              fieldRef:
                fieldPath: spec.nodeName
          - name: NAMESPACE_NAME
            valueFrom:
              fieldRef:
                fieldPath: metadata.namespace
          - name: DEPLOYMENT_NAME
            value: {{ $top.Chart.Name }}
{{- if ne $top.Values.httpsProxy "" }}
          - name: https_proxy
            value: {{ $top.Values.httpsProxy }}
{{- end }}
{{- if ne $top.Values.httpProxy "" }}
          - name: http_proxy
            value: {{ $top.Values.httpProxy }}
{{- end }}
{{- if ne $top.Values.noProxy "" }}
          - name: no_proxy
            value: {{ $top.Values.noProxy }}
{{- end }}
{{- range $top.Values.tpaEnvironmentVariables }}
          - name: {{ .name }}
            value: {{ .value }}
{{- end }}
{{- if eq $bootstrapRefreshTokenFromGcp "true" }}
        command:
          - "/secrets/secrets-init"
        args:
          - "--provider=google"
          - "/entrypoint.sh"
          - "--config"
          - "/conf/agent/agentconfig.yaml"
{{- end }}
        ports:
          - containerPort: {{ $top.Values.serverPort }}
          - containerPort: {{ $top.Values.restServerPort }}
{{- if eq $injectorEnabled true }}
          - containerPort: {{ int $tlsServerPort }}
{{- end }}
{{- if $top.Values.collectorEnabled }}
{{- if $top.Values.collector.receivers.otlp.enabled }}
          - containerPort: {{ $top.Values.collector.ports.opentelemetry }}
{{- end }}
{{- if $top.Values.collector.receivers.otlp.enabled }}
          - containerPort: {{ $top.Values.collector.ports.opentelemetryHttp }}
{{- end }}
{{- if $top.Values.collector.receivers.zipkin.enabled }}
          - containerPort: {{ $top.Values.collector.ports.zipkin }}
{{- end }}
{{- if $top.Values.collector.exporters.prometheus.enabled }}
          - containerPort: {{ $top.Values.collector.ports.prometheus }}
{{- end }}
{{- end }}
        volumeMounts:
          - name: {{ $top.Chart.Name }}-config-map-volume
            mountPath: /conf/agent
{{- if eq $bootstrapRefreshTokenFromGcp "true" }}
          - mountPath: /secrets/
            name: secrets-init-volume
{{- end }}
{{- if eq (include "useExternalTokenSecret" $top) "true" }}
          - name: {{ $top.Chart.Name }}-token-volume
            mountPath: /conf/token
            readOnly: true
{{- end }}
{{- if $addTlsCertsVolume }}
          - name: {{ $top.Chart.Name }}-cert-volume
            mountPath: /conf/certs
            readOnly: true
{{- end }}
          - name: {{ $top.Chart.Name }}-persistence-volume
            mountPath: /conf/persistence
{{- if eq $mirroringEnabled "true"}}
          - name: {{ $top.Chart.Name }}-mirror-volume
            mountPath: {{ $top.Values.daemonSetMirroring.sockAddrVolumePath }}
{{- end }}
{{- if eq $addRemoteTlsCaCertVolume "true" }}
          - name: {{ $top.Chart.Name }}-remote-ca-cert-volume
            mountPath: /conf/remote/certs
            readOnly: true
{{- end }}
{{- if eq $addClientTlsCertKeyVolume "true" }}
          - name: {{ $top.Chart.Name }}-remote-client-cert-key-volume
            mountPath: /conf/remote/client-certs
            readOnly: true
{{- end }}
        resources:
          {{- toYaml $top.Values.resources | nindent 10 }}
        livenessProbe:
          tcpSocket:
            port: {{ $top.Values.restServerPort }}
          initialDelaySeconds: 5
          periodSeconds: 10
        readinessProbe:
          tcpSocket:
            port: {{ $top.Values.restServerPort }}
          initialDelaySeconds: 5
          periodSeconds: 10
{{- if not $top.Values.useCustomSecurityContext }}
{{- if or (eq $tlsServerPort "443") (eq $injectorEnabled true) }}
        securityContext:
          runAsUser: {{ include "tpaContainerSecurityContextUser" $top }}
{{- end }}
{{- else if or $top.Values.securityContext $top.Values.commonContainerSecurityContext }}
        securityContext:
{{- if $top.Values.securityContext }}
{{- toYaml $top.Values.securityContext | nindent 10 }}
{{- else }}
{{- toYaml $top.Values.commonContainerSecurityContext | nindent 10 }}
{{- end }}
{{- end }}
{{- if eq $mirroringEnabled "true" }}
      - name: traceable-mirror
        image: "{{ $registry }}/{{ $top.Values.suricataImageName }}{{ $suricataSeparator }}{{ $top.Values.suricataVersion }}"
        imagePullPolicy: {{ $top.Values.imagePullPolicy }}
        command: ["/bin/sh", "-c" , "/usr/bin/suricata -c /etc/suricata/suricata.yaml --pidfile /var/run/suricata.pid --pcap=any {{ $mirroringBpfFilter }}" ]
        volumeMounts:
          - name: {{ $top.Chart.Name }}-mirror-volume
            mountPath: /var/log/suricata
        resources:
          {{- toYaml $top.Values.daemonSetMirroring.resources | nindent 10 }}
{{- if not $top.Values.useCustomSecurityContext }}
        securityContext:
          runAsUser: 0
{{- else if or $top.Values.mirroringSecurityContext $top.Values.commonContainerSecurityContext }}
        securityContext:
{{- if $top.Values.mirroringSecurityContext }}
{{- toYaml $top.Values.mirroringSecurityContext | nindent 10 }}
{{- else }}
{{- toYaml $top.Values.commonContainerSecurityContext | nindent 10 }}
{{- end }}
{{- end }}
{{- if eq $podMirroringEnabled "true" }}
        ports:
          - containerPort: 4789
{{- end }}
{{- end }}
{{- if $top.Values.grpcToHttp.enabled }}
{{ include "grpcToHttpContainerTemplate" $top | nindent 6 }}
{{- end }}
{{- if $top.Values.extensionService.runWithDeployment }}
      - name: extension-service
        image: "{{ $registry }}/{{ $top.Values.extensionService.imageName }}{{ $extensionServiceImageSeparator }}{{ $top.Values.extensionService.imageVersion }}"
        imagePullPolicy: {{ $top.Values.imagePullPolicy }}
        command: ["python", "app.py"]
        env:
          - name: PORT
            value: {{ $top.Values.extensionService.port | quote }}
        resources:
          {{- toYaml $top.Values.extensionService.resources | nindent 10 }}
        ports:
          - containerPort: {{ $top.Values.extensionService.port }}
{{- if and $top.Values.useCustomSecurityContext (or $top.Values.extensionServiceSecurityContext $top.Values.commonContainerSecurityContext) }}
        securityContext:
{{- if $top.Values.extensionServiceSecurityContext }}
{{- toYaml $top.Values.extensionServiceSecurityContext | nindent 10 }}
{{- else }}
{{- toYaml $top.Values.commonContainerSecurityContext | nindent 10 }}
{{- end }}
{{- end }}
{{- end }}
    volumes:
      - name: {{ $top.Chart.Name }}-config-map-volume
        configMap:
          name: {{ $top.Chart.Name }}-config-map
{{- if eq $bootstrapRefreshTokenFromGcp "true" }}
      - name: secrets-init-volume
        emptyDir: {}
{{- end }}
{{- if eq (include "useExternalTokenSecret" $top) "true" }}
      - name: {{ $top.Chart.Name }}-token-volume
        secret:
          secretName: {{ $top.Values.externalTokenSecret.name }}
          items:
          - key: {{ $top.Values.externalTokenSecret.key }}
            path: refresh-token
{{- end }}
{{- if $addTlsCertsVolume }}
      - name: {{ $top.Chart.Name }}-cert-volume
        secret:
          secretName: {{ $tlsCertSecretName }}
{{- end }}
{{- if ne $top.Values.persistencePvcName "" }}
      - name: {{ $top.Chart.Name }}-persistence-volume
        persistentVolumeClaim:
          claimName: {{ $top.Values.persistencePvcName }}
{{- else }}
      - name: {{ $top.Chart.Name }}-persistence-volume
        emptyDir: {}
{{- end }}
{{- if eq $mirroringEnabled "true" }}
      - name: {{ $top.Chart.Name }}-mirror-volume
        emptyDir: {}
{{- end }}
{{- if eq $addRemoteTlsCaCertVolume "true" }}
      - name: {{ $top.Chart.Name }}-remote-ca-cert-volume
        secret:
          secretName: {{ $remoteTlsCaCertSecretName }}
{{- end }}
{{- if eq $addClientTlsCertKeyVolume "true" }}
      - name: {{ $top.Chart.Name }}-remote-client-cert-key-volume
        secret:
          secretName: {{ $clientTlsCertKeySecretName }}
{{- end }}
{{- if $top.Values.grpcToHttp.enabled }}
{{ include "grpcToHttp.volumes" $top | nindent 6 }}
{{- end }}
{{- if $top.Values.tolerations }}
    tolerations:
      {{- toYaml $top.Values.tolerations | nindent 6 }}
{{- end }}
{{- end }}
