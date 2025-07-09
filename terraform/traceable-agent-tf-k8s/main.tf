# k8s provider
provider "kubernetes" {
  config_path = var.kubernetes_config_path
}

variable "common_name" {
  description = "Common Name"
  default     = "traceable.ai"
}

variable "organization_name" {
  description = "Organization Name"
  default     = "Traceable AI, Inc."
}

module "ca" {
  source            = "./modules/ca"
  ca_common_name    = var.common_name
  organization_name = var.organization_name
}

module "traceable_agent_cert" {
  source             = "./modules/certificate"
  depends_on         = [module.ca.ca_cert_pem, module.ca.ca_private_key_pem, module.ca.ca_cert_pem]
  common_name        = var.common_name
  organization_name  = var.organization_name
  dns_names          = ["agent.${var.namespace}", "agent.${var.namespace}.svc", "agent-injector.${var.namespace}", "agent-injector.${var.namespace}.svc"]
  ca_key_algorithm   = module.ca.ca_key_algorithm
  ca_private_key_pem = module.ca.ca_private_key_pem
  ca_cert_pem        = module.ca.ca_cert_pem
}

locals {
  deployment_name                = "traceable-agent"
  deployment_instance            = "traceableai"
  grpc_http_deployment_instance  = "traceableai-grpc-to-http"
  grpc_http_deployment_name      = "traceable-grpc-to-http-proxy"
  create_private_registry_secret = var.image_credentials.username != "" && var.image_credentials.password != "" && var.image_pull_secret_name == ""
  # We replace "/" with "-" in the registry because of k8s resource name requirements.
  private_registry_regcred         = local.create_private_registry_secret == true ? replace("${var.image_credentials.registry}-regcred", "/", "-") : var.image_pull_secret_name != "" ? var.image_pull_secret_name : ""
  tpa_image_separator              = startswith(var.image_version, "sha256:") ? "@" : ":"
  suricata_image_separator         = startswith(var.suricata_version, "sha256:") ? "@" : ":"
  extension_image_separator        = startswith(var.extension_service.image_version, "sha256:") ? "@" : ":"
  ebpf_image_separator             = startswith(var.ebpf_tracer_version, "sha256:") ? "@" : ":"
  image_pull_secret_auth           = base64encode(format("%s:%s", var.image_credentials.username, var.image_credentials.password))
  image_registry_with_suffix       = var.image_credentials.registry_suffix != "" ? "${var.image_credentials.registry}/${var.image_credentials.registry_suffix}" : var.image_credentials.registry
  traceable_agent_config_map       = "${local.deployment_name}-config-map"
  tls_certs_as_files_enabled       = var.tls_private_certificates_as_files.root_ca_file_name != "" && var.tls_private_certificates_as_files.cert_file_name != "" && var.tls_private_certificates_as_files.key_file_name != ""
  tls_certs_as_secret_enabled      = local.tls_certs_as_files_enabled == false && var.tls_private_certificates_as_secret.secret_name != "" && var.tls_private_certificates_as_secret.root_ca_file_name != "" && var.tls_private_certificates_as_secret.cert_file_name != "" && var.tls_private_certificates_as_secret.key_file_name != ""
  tls_certs_as_strings_enabled     = local.tls_certs_as_secret_enabled == false && var.tls_private_certificates_as_strings.root_ca_b64 != "" && var.tls_private_certificates_as_strings.cert_b64 != "" && var.tls_private_certificates_as_strings.key_b64 != ""
  tls_certs_self_gen               = local.tls_certs_as_files_enabled == false && local.tls_certs_as_secret_enabled == false
  cert_secret_name                 = local.tls_certs_as_secret_enabled == true ? var.tls_private_certificates_as_secret.secret_name : "${local.deployment_name}-cert"
  add_tls_certs                    = var.injector_enabled == true || var.tls_enabled == true
  add_tls_certs_volume             = local.add_tls_certs == true && (local.tls_certs_as_secret_enabled == true || local.tls_certs_self_gen == true || local.tls_certs_as_strings_enabled == true)
  tls_key_file_name                = local.tls_certs_as_files_enabled == true ? var.tls_private_certificates_as_files.key_file_name : local.tls_certs_as_secret_enabled == true ? "/conf/certs/${var.tls_private_certificates_as_secret.key_file_name}" : "/conf/certs/tls.key"
  tls_cert_file_name               = local.tls_certs_as_files_enabled == true ? var.tls_private_certificates_as_files.cert_file_name : local.tls_certs_as_secret_enabled == true ? "/conf/certs/${var.tls_private_certificates_as_secret.cert_file_name}" : "/conf/certs/tls.crt"
  tls_root_ca_cert_file_name       = local.tls_certs_as_files_enabled == true ? var.tls_private_certificates_as_files.root_ca_file_name : local.tls_certs_as_secret_enabled == true ? "/conf/certs/${var.tls_private_certificates_as_secret.root_ca_file_name}" : "/conf/certs/root_ca.crt"
  restart_uuid                     = uuid()
  use_external_token_secret        = var.external_token_secret.name != "" && var.external_token_secret.key != ""
  token_secret_name                = local.use_external_token_secret == true ? var.external_token_secret.name : "token-secret"
  token_secret_key                 = local.use_external_token_secret == true ? var.external_token_secret.key : "token"
  token_file_path                  = "/conf/token/refresh-token"
  remote_tls_ca_cert_secret_set    = var.remote_ca_cert_secret.secret_name != "" && var.remote_ca_cert_secret.ca_cert_file_name != ""
  remote_tls_ca_cert_file_name     = var.remote_ca_bundle != "" ? "/conf/remote/certs/ca_cert.crt" : local.remote_tls_ca_cert_secret_set ? "/conf/remote/certs/${var.remote_ca_cert_secret.ca_cert_file_name}" : var.remote_ca_cert_file != "" ? var.remote_ca_cert_file : ""
  mtls_client_secret_set           = var.remote_client_cert_key_secret.secret_name != "" && var.remote_client_cert_key_secret.client_cert_name != "" && var.remote_client_cert_key_secret.client_key_name != ""
  mtls_client_cert_file_name       = var.remote_client_cert != "" ? "/conf/remote/client-certs/client-cert.pem" : local.mtls_client_secret_set ? "/conf/remote/client-certs/${var.remote_client_cert_key_secret.client_cert_name}" : var.remote_client_cert_file != "" ? var.remote_client_cert_file : ""
  mtls_client_key_file_name        = var.remote_client_key != "" ? "/conf/remote/client-certs/client-key.pem" : local.mtls_client_secret_set ? "/conf/remote/client-certs/${var.remote_client_cert_key_secret.client_key_name}" : var.remote_client_key_file != "" ? var.remote_client_key_file : ""
  add_mtls_certs_volume            = local.mtls_client_secret_set == true || local.mtls_client_cert_file_name != "" || local.mtls_client_key_file_name != ""
  mtls_cert_key_secret_name        = var.remote_client_cert != "" && var.remote_client_key != "" ? "${local.deployment_name}-client-tls" : var.remote_client_cert_key_secret.secret_name != "" ? var.remote_client_cert_key_secret.secret_name : ""
  add_remote_tls_ca_cert_volume    = var.remote_ca_bundle != "" || local.remote_tls_ca_cert_secret_set
  remote_tls_ca_cert_secret_name   = var.remote_ca_bundle != "" ? "${local.deployment_name}-remote-ca-cert" : var.remote_ca_cert_secret.secret_name
  traceable_ebpf_config_map        = "${local.deployment_name}-ebpf-config-map"
  ebpf_allowed_capabilities        = var.ebpf_capture_enabled == true ? var.ebpf_allowed_capabilities : []
  injector_allowed_capabilities    = var.injector_enabled == true ? var.injector_allowed_capabilities : []
  bootstrap_refresh_token_from_gcp = var.refresh_token_gcp_secret_project != "" && var.refresh_token_gcp_secret_name != ""

  allowed_content_types = length(var.allowed_content_types) == 0 ? "allowed_content_types: []" : <<EOF
allowed_content_types:
  ${indent(2, yamlencode(var.allowed_content_types))}
EOF

  ebpf_service_name_labels = length(var.ebpf_service_name_labels) == 0 ? "service_name_labels: []" : <<EOF
service_name_labels:
  ${indent(2, yamlencode(var.ebpf_service_name_labels))}
EOF

  ebpf_libssl_prefixes = length(var.ebpf_libssl_prefixes) == 0 ? "libssl_prefixes: []" : <<EOF
libssl_prefixes:
  ${indent(2, yamlencode(var.ebpf_libssl_prefixes))}
EOF

  ebpf_exclude_processes = length(var.ebpf_exclude_processes) == 0 ? "exclude_processes: []" : <<EOF
exclude_processes:
  ${indent(2, yamlencode(var.ebpf_exclude_processes))}
EOF

  ebpf_uprobe_attach_exclusion_rules = length(var.ebpf_uprobe_attach_exclusion_rules) == 0 ? "uprobe_attach_exclusion_rules: []" : <<EOF
uprobe_attach_exclusion_rule:
  ${indent(2, yamlencode(var.ebpf_uprobe_attach_exclusion_rules))}
EOF

  ebpf_ssl_keylog_include_rules = length(var.ebpf_ssl_keylog_include_rules) == 0 ? "ssl_keylog_include_rules: []" : <<EOF
ssl_keylog_include_rules:
  ${indent(2, yamlencode(var.ebpf_ssl_keylog_include_rules))}
EOF

  ebpf_pod_labels = length(var.ebpf_pod_labels) == 0 ? "pod_labels: []" : <<EOF
pod_labels:
  ${indent(2, yamlencode(var.ebpf_pod_labels))}
EOF

  ebpf_pod_annotations = length(var.ebpf_pod_annotations) == 0 ? "pod_annotations: []" : <<EOF
pod_annotations:
  ${indent(2, yamlencode(var.ebpf_pod_annotations))}
EOF

  ebpf_custom_span_attributes = length(var.ebpf_custom_span_attributes) == 0 ? "" : <<EOF
custom_span_attributes:
  ${indent(2, yamlencode(var.ebpf_custom_span_attributes))}
EOF

  tpa_command_list = local.bootstrap_refresh_token_from_gcp == true ? ["/secrets/secrets-init"] : []
  tpa_args_list    = local.bootstrap_refresh_token_from_gcp == true ? ["--provider=google", "/entrypoint.sh", "--config", "/conf/agent/agentconfig.yaml"] : []

  # We open up some ports
  collector_ports_0 = var.collector.receivers.otlp.enabled == false ? [] : [
    {
      name           = "grpc-otlp"
      container_port = var.collector.ports.opentelemetry
      service_port   = var.collector.ports.opentelemetry
    },
    {
      name           = "http-otlp"
      container_port = var.collector.ports.opentelemetry_http
      service_port   = var.collector.ports.opentelemetry_http
    }
  ]
  collector_ports_1 = var.collector.receivers.zipkin.enabled == false ? local.collector_ports_0 : concat(local.collector_ports_0, [
    {
      name           = "http-zipkin"
      container_port = var.collector.ports.zipkin
      service_port   = var.collector.ports.zipkin
    }
  ])
  collector_ports_2 = var.collector.exporters.prometheus.enabled == false ? local.collector_ports_1 : concat(local.collector_ports_1, [
    {
      name           = "http-prometheus"
      container_port = var.collector.ports.prometheus
      service_port   = var.collector.ports.prometheus
    }
  ])
  collector_ports = local.collector_ports_2

  image_pull_secrets          = local.private_registry_regcred != "" ? [local.private_registry_regcred] : []
  image_pull_credentials_json = <<EOF
    {
      "auths": {
        "${var.image_credentials.registry}":{
          "auth": "${local.image_pull_secret_auth}"
        }
      }
    }
    EOF

  labels = merge({
    "app.kubernetes.io/name"       = local.deployment_name
    "app.kubernetes.io/instance"   = local.deployment_instance
    "app.kubernetes.io/version"    = var.image_version
    "app.kubernetes.io/managed-by" = "Terraform"
  }, var.additional_global_labels)

  global_annotations = var.additional_global_annotations

  service_labels      = merge(local.labels, var.service_labels)
  service_annotations = merge(var.additional_global_annotations, var.service_annotations)

  service_account_annotations = length(var.gke_service_account) == 0 ? {} : { "iam.gke.io/gcp-service-account" = var.gke_service_account }

  deployment_annotations = merge({
    "restart-trigger-uuid" = local.restart_uuid
  }, var.additional_annotations)

  collector_traces_receivers_arr_0 = var.collector.receivers.otlp.enabled == false ? [] : ["otlp"]
  collector_traces_receivers_arr_1 = var.collector.receivers.zipkin.enabled == false ? local.collector_traces_receivers_arr_0 : concat(local.collector_traces_receivers_arr_0, ["zipkin"])
  collector_traces_receivers       = format("[%s]", join(", ", local.collector_traces_receivers_arr_1))

  collector_metrics_receivers_arr_0 = var.collector.receivers.otlp.enabled == false ? [] : ["otlp"]
  collector_metrics_receivers       = format("[%s, prometheus]", join(", ", local.collector_metrics_receivers_arr_0))

  # Defining the traces processor pipeline. The order matters. When all supported processors are configured this is the order:
  # [k8sattributes, traceable_servicenamerprocessor, traceable_spanremover, traceable_traces_buffer, traceable_barespanconverter, traceable_protoprocessor,
  #   traceable_base64decoderprocessor, traceable_dataparser,
  #   traceable_dataclassification, traceable_modsec, traceable_metadata, batch]
  collector_processors_arr_0  = []
  collector_processors_arr_1  = var.k8sprocessor_enabled == false ? local.collector_processors_arr_0 : concat(local.collector_processors_arr_0, ["k8sattributes"])
  collector_processors_arr_5  = var.servicenamerprocessor_enabled == false ? local.collector_processors_arr_1 : concat(local.collector_processors_arr_1, ["traceable_servicenamerprocessor"])
  collector_processors_arr_10 = length(var.span_remover_processor) == 0 ? local.collector_processors_arr_5 : concat(local.collector_processors_arr_5, ["traceable_spanremover"])
  collector_processors_arr_15 = var.traces_buffering_processor_enabled == false ? local.collector_processors_arr_10 : concat(local.collector_processors_arr_10, ["traceable_traces_buffer"])
  collector_processors_arr_20 = length(var.additional_trace_preprocessing_pipeline) == 0 ? local.collector_processors_arr_15 : concat(local.collector_processors_arr_15, var.additional_trace_preprocessing_pipeline)
  collector_processors_arr_25 = length(var.bare_span_converter_processor) == 0 ? local.collector_processors_arr_20 : concat(local.collector_processors_arr_20, ["traceable_barespanconverter"])
  collector_processors_arr_30 = length(var.ip_resolution_processor) == 0 ? local.collector_processors_arr_25 : concat(local.collector_processors_arr_25, ["traceable_ipresolutionprocessor"])
  collector_processors_arr_35 = var.protoprocessor == "" ? local.collector_processors_arr_30 : concat(local.collector_processors_arr_30, ["traceable_protoprocessor"])
  collector_processors_arr_40 = var.base64decoderprocessor == "" ? local.collector_processors_arr_35 : concat(local.collector_processors_arr_35, ["traceable_base64decoderprocessor"])
  collector_processors_arr_45 = concat(local.collector_processors_arr_40, ["traceable_attributes"])
  collector_processors_arr_50 = concat(local.collector_processors_arr_45, ["traceable_dataparser"])
  collector_processors_arr_55 = concat(local.collector_processors_arr_50, ["traceable_dataclassification"])
  collector_processors_arr_60 = concat(local.collector_processors_arr_55, ["traceable_modsec"])
  collector_processors_arr_65 = concat(local.collector_processors_arr_60, ["traceable_metadata"])
  collector_processors        = format("[%s, batch]", join(", ", local.collector_processors_arr_65))

  # Defining the traces/internal_spans processor pipeline.:
  # [transform/environment, filter/internal_spans, batch]
  collector_internal_spans_processors_arr_0 = ["transform/environment"]
  collector_internal_spans_processors_arr_1 = concat(local.collector_internal_spans_processors_arr_0, ["filter/internal_spans"])
  collector_internal_spans_processors_arr_2 = length(var.additional_trace_internal_span_processors) == 0 ? local.collector_internal_spans_processors_arr_1 : concat(local.collector_internal_spans_processors_arr_1, var.additional_trace_internal_span_processors)
  collector_internal_spans_processors       = format("[%s, batch]", join(", ", local.collector_internal_spans_processors_arr_2))

  injector_service_host_name = var.injector_enabled == true && var.service_type == "Headless" ? "agent-injector" : "agent"

  servicenamerprocessor_config = var.servicenamerprocessor_enabled == false ? "" : <<EOF
traceable_servicenamerprocessor:
EOF
  k8sprocessor_config          = var.k8sprocessor_enabled == false ? "" : <<EOF
k8sattributes:
  passthrough: false
  auth_type: "serviceAccount"
  extract:
    metadata:
      - k8s.pod.name
      - k8s.pod.uid
      - k8s.deployment.name
      - k8s.namespace.name
      - k8s.node.name
      - k8s.pod.start_time
EOF

  span_remover_processor_config = length(var.span_remover_processor) == 0 ? "" : <<EOF
traceable_spanremover:
  ${indent(2, yamlencode(var.span_remover_processor))}
EOF

  bare_span_converter_processor_config = length(var.bare_span_converter_processor) == 0 ? "" : <<EOF
traceable_barespanconverter:
  ${indent(2, yamlencode(var.bare_span_converter_processor))}
EOF

  ip_resolution_processor_config = length(var.ip_resolution_processor) == 0 ? "" : <<EOF
traceable_ipresolutionprocessor:
  ${indent(2, yamlencode(var.ip_resolution_processor))}
EOF

  batch_processor_agent_token_config = var.batch_processor_create_batch_per_token_enabled == false ? "" : <<EOF
metadata_keys:
  - traceableai-agent-token
EOF

  nginx_capture_content_types = length(var.injector.nginx_cpp.config.capture_content_types) == 0 ? "" : <<EOF
capture_content_types:
${yamlencode(var.injector.nginx_cpp.config.capture_content_types)}
EOF


  otlpreceiver_config   = var.collector.receivers.otlp.enabled == false ? "" : <<EOF
otlp:
  protocols:
    grpc:
      include_metadata: true
      max_recv_msg_size_mib: ${var.collector.receivers.otlp.max_recv_msg_size_mib}
      endpoint: "127.0.0.1:${var.collector.ports.opentelemetry}"
      auth:
        authenticator: traceable_tokenauth/server
      keepalive:
        server_parameters:
          max_connection_age: ${var.collector.receivers.otlp.max_connection_age}
    http:
      include_metadata: true
      endpoint: "127.0.0.1:${var.collector.ports.opentelemetry_http}"
      auth:
        authenticator: traceable_tokenauth/server
EOF
  zipkinreceiver_config = var.collector.receivers.zipkin.enabled == false ? "" : <<EOF
zipkin:
  endpoint: "127.0.0.1:${var.collector.ports.zipkin}"
  auth:
    authenticator: traceable_tokenauth/server
EOF

  prometheus_exporter_config = var.collector.exporters.prometheus.enabled == false ? "" : <<EOF
prometheus:
  endpoint: "127.0.0.1:${var.collector.ports.prometheus}"
  namespace: traceableai
EOF

  tls_server_config = local.add_tls_certs == false ? "" : <<EOF
tls_server:
  endpoint: "0.0.0.0:${var.tls_server_port}"
  key_file: "${local.tls_key_file_name}"
  cert_file: "${local.tls_cert_file_name}"
  root_cert_file: "${local.tls_root_ca_cert_file_name}"
  idle_timeout: ${var.tls_server_idle_timeout}
  disable_keep_alive: ${var.tls_server_disable_keep_alive}
EOF

  # Note that we do not call base64encode on these 3 locals.
  # We decode var.injector.ca_bundle since it will be re-encoded when creating the mutating webhook config.
  ca_bundle = var.injector.ca_bundle != "" ? base64decode(var.injector.ca_bundle) : module.ca.ca_cert_pem
  tls_key   = module.traceable_agent_cert.cert_private_key_pem
  tls_crt   = module.traceable_agent_cert.cert_public_key_pem

  injector_propagation_formats               = var.injector.propagation_formats == [] ? "" : yamlencode({ propagation_formats = var.injector.propagation_formats })
  injector_reporting_endpoint_port           = var.tls_enabled == true ? var.tls_server_port : var.http_reverse_proxy_enabled ? var.rest_server_port : var.injector.trace_reporter_type == "OTLP" ? var.collector.ports.opentelemetry : var.collector.ports.zipkin
  injector_remote_config_endpoint_port       = var.tls_enabled == true ? var.tls_server_port : var.http_reverse_proxy_enabled ? var.rest_server_port : var.server_port
  injector_capture_content_type              = var.injector.capture_content_type == [] ? "" : yamlencode({ capture_content_type = var.injector.capture_content_type })
  injector_images_repository                 = local.image_registry_with_suffix
  injector_nginx_image_version               = var.injector.nginx.image_version == "" ? var.image_version : var.injector.nginx.image_version
  injector_nginx_cpp_reporting_endpoint_port = var.tls_enabled == true ? var.tls_server_port : var.http_reverse_proxy_enabled ? var.rest_server_port : var.collector.ports.zipkin
  injector_tme_image_version                 = var.injector.tme.image_version == "" ? var.image_version : var.injector.tme.image_version
  injector_haproxy_image_version             = var.injector.haproxy.image_version == "" ? var.image_version : var.injector.haproxy.image_version
  injector_wasm_image_version                = var.injector.wasm.image_version == "" ? var.image_version : var.injector.wasm.image_version
  persistence_directory                      = "/conf/persistence"
  persistence_pvc_config_map_val             = var.persistence_pvc_name == "" ? "" : yamlencode({ persistence_directory = local.persistence_directory })
  collector_exporter_otlp_compression        = var.collector.exporters.otlp.compression == "" ? "" : yamlencode({ compression = var.collector.exporters.otlp.compression })
  loopback_http_protocol                     = var.tls_enabled == true ? "https" : "http"
  daemon_set_mirroring                       = var.run_as_daemon_set == true && var.daemon_set_mirroring_enabled == true
  daemon_set_mirror_all_namespaces           = (local.daemon_set_mirroring == true) && (var.daemon_set_mirror_all_namespaces == true)
  ebpf_remote_endpoint_port                  = var.tls_enabled == true ? var.tls_server_port : var.http_reverse_proxy_enabled ? var.rest_server_port : var.server_port
  ebpf_reporting_endpoint_port               = var.tls_enabled == true ? var.tls_server_port : var.http_reverse_proxy_enabled ? var.rest_server_port : (var.ebpf_trace_reporter_type == "OTLP" ? var.collector.ports.opentelemetry : var.collector.ports.zipkin)
  # scheme and path is only needed for zipkin
  ebpf_reporting_endpoint_scheme  = var.ebpf_trace_reporter_type == "ZIPKIN" ? (var.tls_enabled == true ? "https://" : "http://") : ""
  ebpf_reporting_endpoint_path    = var.ebpf_trace_reporter_type == "ZIPKIN" ? "/api/v2/spans" : ""
  ebpf_reporting_endpoint         = var.ebpf_only == false ? "${local.ebpf_reporting_endpoint_scheme}agent.${var.namespace}:${local.ebpf_reporting_endpoint_port}${local.ebpf_reporting_endpoint_path}" : var.ebpf_reporting_endpoint
  ebpf_remote_endpoint            = var.ebpf_only == false ? "agent.${var.namespace}:${local.ebpf_remote_endpoint_port}" : var.ebpf_remote_endpoint
  ebpf_environment                = length(var.ebpf_environment) == 0 ? "" : yamlencode({ environment = var.ebpf_environment })
  ebpf_custom_ssl_address         = length(var.ebpf_custom_ssl_address) == 0 ? "" : <<EOF
custom_ssl_address:
${yamlencode(var.ebpf_custom_ssl_address)}
EOF
  ebpf_logging_error_output_paths = length(var.ebpf_logging.error_output_paths) == 0 ? "" : <<EOF
error_output_paths:
${yamlencode(var.ebpf_logging.error_output_paths)}
EOF
  ebpf_log_level                  = var.ebpf_logging.level == null ? var.ebpf_log_level : var.ebpf_logging.level
  ebpf_mem_limit                  = var.ebpf_enable_go_memory_limit == true ? var.daemon_set_mirroring.resources.limits.memory : "0"
  ebpf_host_proc                  = var.ebpf_enable_java_tls_capture == true || length(var.ebpf_ssl_keylog_include_rules) > 0 ? "/proc" : "/hostproc"
  pod_mirroring_enabled           = (var.injector_enabled == true && var.pod_mirroring_enabled == true)
  mirroring_enabled               = (local.daemon_set_mirroring == true) || (local.pod_mirroring_enabled == true)
  mirroring_bpf_filter            = local.daemon_set_mirroring == true ? "not net 127.0.0.0/8" : "not net 127.0.0.0/8 and port 4789"
  daemon_set_match_selectors      = length(var.daemon_set_mirroring.match_selectors) == 0 ? "" : <<EOF
match_selectors:
${yamlencode(var.daemon_set_mirroring.match_selectors)}
EOF

  daemon_set_match_selectors_egress = length(var.daemon_set_mirroring.match_selectors_egress) == 0 ? "" : <<EOF
match_selectors_egress:
${yamlencode(var.daemon_set_mirroring.match_selectors_egress)}
EOF

  daemon_set_match_selectors_ingress_and_egress = length(var.daemon_set_mirroring.match_selectors_ingress_and_egress) == 0 ? "" : <<EOF
match_selectors_ingress_and_egress:
${yamlencode(var.daemon_set_mirroring.match_selectors_ingress_and_egress)}
EOF

  pods_watch_match_selectors_config = <<EOF
pods_selectors:
  ${indent(2, yamlencode(var.ebpf_watch_match_selectors.pods_selectors))}
EOF

  namespaces_watch_match_selectors_config = <<EOF
namespaces_selectors:
  ${indent(2, yamlencode(var.ebpf_watch_match_selectors.namespaces_selectors))}
EOF

  blocking_enabled = var.blocking_enabled == true && local.mirroring_enabled == false

  java_match_selectors = length(var.injector.java.match_selectors) == 0 ? "" : <<EOF
match_selectors:
  ${indent(2, yamlencode(var.injector.java.match_selectors))}
EOF

  tme_match_selectors = length(var.injector.tme.match_selectors) == 0 ? "" : <<EOF
match_selectors:
  ${indent(2, yamlencode(var.injector.tme.match_selectors))}
EOF

  nginx_match_selectors = length(var.injector.nginx.match_selectors) == 0 ? "" : <<EOF
match_selectors:
  ${indent(2, yamlencode(var.injector.nginx.match_selectors))}
EOF

  nginx_cpp_match_selectors = length(var.injector.nginx_cpp.match_selectors) == 0 ? "" : <<EOF
match_selectors:
  ${indent(2, yamlencode(var.injector.nginx_cpp.match_selectors))}
EOF

  mirror_match_selectors = length(var.injector.mirror.match_selectors) == 0 ? "" : <<EOF
match_selectors:
  ${indent(2, yamlencode(var.injector.mirror.match_selectors))}
EOF

  mirror_match_selectors_egress = length(var.injector.mirror.match_selectors_egress) == 0 ? "" : <<EOF
match_selectors_egress:
  ${indent(2, yamlencode(var.injector.mirror.match_selectors_egress))}
EOF

  mirror_match_selectors_ingress_and_egress = length(var.injector.mirror.match_selectors_ingress_and_egress) == 0 ? "" : <<EOF
match_selectors_ingress_and_egress:
  ${indent(2, yamlencode(var.injector.mirror.match_selectors_ingress_and_egress))}
EOF

  pod_mirroring_match_selectors = length(var.injector.mirror.match_selectors) == 0 ? "" : <<EOF
pod_mirroring_match_selectors:
  ${indent(2, yamlencode(var.injector.mirror.match_selectors))}
EOF

  pod_mirroring_match_selectors_egress = length(var.injector.mirror.match_selectors_egress) == 0 ? "" : <<EOF
pod_mirroring_match_selectors_egress:
  ${indent(2, yamlencode(var.injector.mirror.match_selectors_egress))}
EOF

  pod_mirroring_match_selectors_ingress_and_egress = length(var.injector.mirror.match_selectors_ingress_and_egress) == 0 ? "" : <<EOF
pod_mirroring_match_selectors_ingress_and_egress:
  ${indent(2, yamlencode(var.injector.mirror.match_selectors_ingress_and_egress))}
EOF

  haproxy_match_selectors = length(var.injector.haproxy.match_selectors) == 0 ? "" : <<EOF
match_selectors:
  ${indent(2, yamlencode(var.injector.haproxy.match_selectors))}
EOF

  extension_service_match_selectors = length(var.extension_service.match_selectors) == 0 ? "" : <<EOF
  ${indent(2, yamlencode(var.extension_service.match_selectors))}
EOF

  create_tme_webhook_match_labels = length(var.injector.tme.match_selectors) == 0 && length(var.injector.nginx.match_selectors) == 0 && length(var.injector.haproxy.match_selectors) == 0

  java_webhook_match_labels = length(var.injector.java.match_selectors) == 0 ? {
    "traceableai-inject-java" = "enabled"
  } : {}

  tme_webhook_match_labels = local.create_tme_webhook_match_labels ? {
    "traceableai-inject-tme" = "enabled"
  } : {}

  mirror_webhook_match_labels = length(var.injector.mirror.match_selectors) == 0 ? {
    "traceableai-inject-mirror" = "enabled"
  } : {}

  extension_webhook_match_labels = length(var.extension_service.match_selectors) == 0 ? {
    "traceableai-inject-extension" = "enabled"
  } : {}

  nginx_cpp_match_labels = length(var.injector.nginx_cpp.match_selectors) == 0 ? {
    "traceableai-inject-nginx-cpp" = "enabled"
  } : {}

  java_deprecated_webhook_match_labels = {
    "traceableai-instrumentation" = "enabled"
  }

  tme_deprecated_webhook_match_labels = {
    "traceableai-instrumentation" = "enabled"
  }

  otlp_collector_extensions   = var.persistent_queue_enabled == false ? format("[%s]", join(", ", ["traceable_tokenauth/server", "health_check"])) : format("[%s]", join(", ", ["traceable_tokenauth/server", "health_check", "file_storage"]))
  otlp_exporter_sending_queue = var.persistent_queue_enabled == false ? "" : <<EOF
sending_queue:
  storage: file_storage
EOF

  file_storage_extension = var.persistent_queue_enabled == false ? "" : <<EOF
file_storage:
  directory: "${local.persistence_directory}"
  timeout: 1s
  compaction:
    on_start: true
    on_rebound: true
    directory: "${local.persistence_directory}"
    max_transaction_size: 65_536
EOF

  # traces buffering processor
  cpu_limit_int                  = endswith(var.resources.limits.cpu, "m") ? floor(parseint(trimsuffix(var.resources.limits.cpu, "m"), 10) / 1000) : floor(tonumber(var.resources.limits.cpu))
  traces_buffering_no_of_workers = var.traces_buffering_processor.no_of_workers == 0 ? max(2, local.cpu_limit_int) : var.traces_buffering_processor.no_of_workers
  # traces_buffering_no_of_workers = max(2, local.traces_buffering_no_of_workers_tmp)
  traces_buffering_processor_config = var.traces_buffering_processor_enabled == false ? "" : <<EOF
traceable_traces_buffer:
  buffer_capacity: ${var.traces_buffering_processor.buffer_capacity}
  no_of_workers: ${local.traces_buffering_no_of_workers}
  send_buffer_overflow_spans: ${var.traces_buffering_processor.send_buffer_overflow_spans}
EOF

  metric_remover_processor_config = <<EOF
traceable_metricremover:
  ${indent(2, yamlencode(var.metric_remover_processor))}
EOF

  filter_internal_spans_config = <<EOF
filter/internal_spans:
  ${indent(2, yamlencode(var.filter_internal_spans_processor))}
EOF
  filter_external_spans_config = <<EOF
filter/external_spans:
  ${indent(2, yamlencode(var.filter_external_spans_processor))}
EOF
  additional_processor_config  = length(keys(var.collector.additional_processors)) == 0 ? "" : yamlencode(var.collector.additional_processors)

  cluster_role_daemon_set_mirroring_rules = [
    {
      api_groups = [""]
      resources  = ["namespaces", "pods"]
      verbs      = ["get", "watch", "list"]
    },
    {
      api_groups = [""]
      resources  = ["services"]
      verbs      = ["list"]
    }
  ]

  grpc_to_http_tls_config  = var.grpc_to_http.server_cert_secret_name == "" ? "" : <<EOF
transport_socket:
  name: envoy.transport_sockets.tls
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
    common_tls_context:
      tls_certificates:
        - certificate_chain:
            filename: "/etc/certs/server.crt"
          private_key:
            filename: "/etc/certs/server.key"
EOF
  grpc_to_http_auth_config = var.grpc_to_http.proxy_credentials_encoded == "" ? "" : <<EOF
headers_to_add:
  - header:
      key: Proxy-Authorization
      value: "Basic ${var.grpc_to_http.proxy_credentials_encoded}"
    append: false
EOF

  ebpf_to_tpa_tls_enabled                 = var.ebpf_only == false ? var.tls_enabled : var.ebpf_to_tpa_tls_enabled
  add_tpa_tls_ca_cert_for_clients_volume  = var.ebpf_only == false ? var.tls_enabled && local.add_tls_certs_volume : var.tpa_ca_bundle != "" || (var.tpa_ca_cert_secret.secret_name != "" && var.tpa_ca_cert_secret.ca_cert_file_name != "")
  tpa_tls_ca_cert_for_clients_secret_name = var.ebpf_only == false ? local.cert_secret_name : var.tpa_ca_bundle != "" ? "${local.deployment_name}-tpa-ca-cert" : var.tpa_ca_cert_secret.secret_name
  ebpf_only_tls_ca_cert_file_name         = var.tpa_ca_bundle != "" ? "/conf/certs/ca_cert.crt" : (var.tpa_ca_cert_secret.secret_name != "" && var.tpa_ca_cert_secret.ca_cert_file_name != "") ? "/conf/certs/${var.tpa_ca_cert_secret.ca_cert_file_name}" : var.tpa_ca_cert_file != "" ? var.tpa_ca_cert_file : ""
  tpa_tls_ca_cert_for_clients_file_name   = var.ebpf_only == false ? local.tls_root_ca_cert_file_name : local.ebpf_only_tls_ca_cert_file_name

  edge_decision_svc_include_regexes = length(var.ext_cap_edge_decision_service.include_path_regexes) == 0 ? "" : <<EOF
include_path_regexes:
 ${indent(2, yamlencode(var.ext_cap_edge_decision_service.include_path_regexes))}
EOF

  edge_decision_svc_exclude_regexes = length(var.ext_cap_edge_decision_service.exclude_path_regexes) == 0 ? "" : <<EOF
exclude_path_regexes:
 ${indent(2, yamlencode(var.ext_cap_edge_decision_service.exclude_path_regexes))}
EOF

  bot_svc_include_path_prefixes = length(var.ext_cap_bot_service.include_path_prefixes) == 0 ? "" : <<EOF
include_path_prefixes:
 ${indent(2, yamlencode(var.ext_cap_bot_service.include_path_prefixes))}
EOF

  injector_edge_decision_svc_include_regexes = length(var.injector.blocking_config.edge_decision_service.include_path_regexes) == 0 ? "" : <<EOF
include_path_regexes:
 ${indent(2, yamlencode(var.injector.blocking_config.edge_decision_service.include_path_regexes))}
EOF

  injector_edge_decision_svc_exclude_regexes = length(var.injector.blocking_config.edge_decision_service.exclude_path_regexes) == 0 ? "" : <<EOF
exclude_path_regexes:
 ${indent(2, yamlencode(var.injector.blocking_config.edge_decision_service.exclude_path_regexes))}
EOF

  injector_bot_svc_include_prefixes = length(var.injector.bot_service.include_path_prefixes) == 0 ? "" : <<EOF
include_path_prefixes:
  ${indent(2, yamlencode(var.injector.bot_service.include_path_prefixes))}
EOF

  telemetry_reporting_endpoint = var.telemetry_reporting_endpoint != "" ? var.telemetry_reporting_endpoint : "localhost:${var.collector.ports.opentelemetry}"
  single_service_mode          = var.single_service_mode && var.http_reverse_proxy_enabled ? true : false
}
