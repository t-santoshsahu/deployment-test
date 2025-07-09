resource "kubernetes_config_map" "traceable-agent-ebpf-config-map" {
  count = var.ebpf_capture_enabled == true ? 1 : 0
  metadata {
    name        = local.traceable_ebpf_config_map
    namespace   = var.namespace
    labels      = local.labels
    annotations = var.additional_global_annotations
  }
  data = {
    "ebpfconfig.yaml" = <<EOF
    ## ebpf tracer config file ##

    ## environment attribute for ebpf agent
    ${indent(4, local.ebpf_environment)}

    ## set proc filesystem. ebpf-tracer needs it to get process metadata
    proc_fs_path: "${local.ebpf_host_proc}"

    ## sizing parameters. Memory usage depends on these queue sizes
    perfmap_queue_size: 1024
    probe_event_queue_size: ${var.ebpf_probe_event_queue_size}

    ## capture mode, allowed values are ingress and egress
    mode: "ingress"

    # exclude processes from capturing
    ${indent(4, local.ebpf_exclude_processes)}

    # uprobe attach exclusion rules
    ${indent(4, local.ebpf_uprobe_attach_exclusion_rules)}

    # ssl keylog inclusion rules
    ${indent(4, local.ebpf_ssl_keylog_include_rules)}

    ## Maximum parallel return probe
    max_active_ret_probe: ${var.ebpf_max_active_ret_probe}

    ## enable uprobes
    enable_uprobes: true

    ## enable tracepoints
    enable_tracepoints: ${var.ebpf_enable_tracepoints}

    # limit to process requests in a second
    request_per_second_limit: ${var.ebpf_request_per_second_limit}

    # Max connection to track
    max_connection: ${var.ebpf_max_connection}

    ## k8s config parameters
    # set to true if running in k8s environment
    k8s_enabled: true
    # set to true to capture from all namespaces
    capture_all_namespaces: ${var.daemon_set_mirror_all_namespaces}
    ${indent(4, local.daemon_set_match_selectors)}
    ${indent(4, local.daemon_set_match_selectors_egress)}
    ${indent(4, local.daemon_set_match_selectors_ingress_and_egress)}
    ${indent(4, local.ebpf_service_name_labels)}

    ${indent(4, local.ebpf_libssl_prefixes)}

    # ebpf custom ssl read write address
    ${indent(4, local.ebpf_custom_ssl_address)}

    # service name
    service_name: "${var.ebpf_default_service_name}"
    use_single_tracer: ${var.ebpf_use_single_tracer}

    # Enable http2(including grpc) data capture
    http2_data_capture_enabled: ${var.ebpf_http2_capture_enabled}

    # enable capture from java tls process
    enable_java_tls_capture: ${var.ebpf_enable_java_tls_capture}

    # Expose http server based Go Profiling
    enable_pprof_http: ${var.ebpf_enable_pprof_http}
    pprof_port: ${var.ebpf_pprof_port}

    proc_fs_scan_period_in_sec: ${var.ebpf_proc_fs_scan_period_in_sec}

    btf:
      download_storage_path: "${var.ebpf_btf_downloads_path}"

    # Export metrics to Traceable Platform
    metrics_enabled: ${var.ebpf_metrics_enabled}

    # Substitute of GOMEMLIMIT environment variable. Expects input in k8s units. The default value is 0,
    # in which case no limit is set. Examples: 128974848, 129e6, 129M,  128974848000m, 123Mi
    # ref: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/#meaning-of-memory
    go_memory_limit: "${local.ebpf_mem_limit}"

    # Logging config for eBPF. Allowed values for level are trace, debug, info, warn and error
    logging:
      level: ${local.ebpf_log_level}
      encoding: ${var.ebpf_logging.encoding}
      ${indent(6, local.ebpf_logging_error_output_paths)}

    watch_selectors:
      enabled: ${var.ebpf_watch_match_selectors.enabled}
      ${indent(6, local.pods_watch_match_selectors_config)}
      ${indent(6, local.namespaces_watch_match_selectors_config)}

    # pod labels to capture
    ${indent(4, local.ebpf_pod_labels)}

    # pod annotations to capture
    ${indent(4, local.ebpf_pod_annotations)}

    # custom span attributes
    ${indent(4, local.ebpf_custom_span_attributes)}

    # goagent config parameters
    agent_config:
      ## enable sampling
      sampling: ${var.sampling_enabled}
      ## if client needs to use tls
      secure: ${local.ebpf_to_tpa_tls_enabled}
      ## path of the ca certificate file
      ca_cert_file: "${local.tpa_tls_ca_cert_for_clients_file_name}"
      reporting:
        endpoint: "${local.ebpf_reporting_endpoint}"
        trace_reporter_type: "${var.ebpf_trace_reporter_type}"
      data_capture:
        body_max_size_bytes: ${var.max_body_size}
        ${indent(8, local.allowed_content_types)}
      # remote config
      remote:
        endpoint: "${local.ebpf_remote_endpoint}"
        poll_period_seconds: ${var.remote_config_poll_period}
        grpc_max_call_recv_msg_size: ${var.remote_grpc_max_call_recv_msg_size}
      # default rate limit config
      default_rate_limit_config:
        enabled: ${var.ebpf_default_rate_limit_config.enabled}
        max_count_global: ${var.ebpf_default_rate_limit_config.max_count_global}
        max_count_per_endpoint: ${var.ebpf_default_rate_limit_config.max_count_per_endpoint}
        refresh_period: "${var.ebpf_default_rate_limit_config.refresh_period}"
        value_expiration_period: "${var.ebpf_default_rate_limit_config.value_expiration_period}"
        span_type: ${var.ebpf_default_rate_limit_config.span_type}
      use_custom_bsp: ${var.ebpf_use_custom_bsp}
      logging:
        log_mode: LOG_MODE_STDOUT
        log_level: ${var.ebpf_filter_log_level}
      metrics_config:
        enabled: ${var.ebpf_filter_metrics_config.enabled}
        endpoint_config:
          enabled: ${var.ebpf_filter_metrics_config.endpoint_config.enabled}
          max_endpoints: ${var.ebpf_filter_metrics_config.endpoint_config.max_endpoints}
          logging:
            enabled: ${var.ebpf_filter_metrics_config.endpoint_config.logging.enabled}
            frequency: ${var.ebpf_filter_metrics_config.endpoint_config.logging.frequency}
        logging:
          enabled: ${var.ebpf_filter_metrics_config.logging.enabled}
          frequency: ${var.ebpf_filter_metrics_config.logging.frequency}
    EOF
  }
}
