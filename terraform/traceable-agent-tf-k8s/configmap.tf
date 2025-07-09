resource "kubernetes_config_map" "traceable-agent-config-map" {
  count = var.ebpf_only == false ? 1 : 0
  metadata {
    name        = local.traceable_agent_config_map
    namespace   = var.namespace
    labels      = local.labels
    annotations = var.additional_global_annotations
  }
  data = {
    "agentconfig.yaml" = <<EOF
    global:
      logging:
        level: ${var.log_level}
        encoding: "${var.log_encoding}"
        output_paths:
          - stdout
        error_output_paths:
          - stderr
        encoder_config:
          time_key: "time"
          time_encoder: "iso8601"
          level_key: "level"
          level_encoder: "uppercase"
          message_key: "message"
      server:
        endpoint: "0.0.0.0:${var.server_port}"
        keepalive:
          server_parameters:
            max_connection_age: ${var.server_port_max_connection_age}
      rest_server:
        endpoint: "0.0.0.0:${var.rest_server_port}"
        idle_timeout: ${var.rest_server_idle_timeout}
        disable_keep_alive: ${var.rest_server_disable_keep_alive}
      ${indent(6, local.tls_server_config)}
      hsl_server:
        enabled: ${var.hsl_server.enabled}
        delimiter: ${var.hsl_server.delimiter}
        server:
          endpoint: "0.0.0.0:${var.hsl_server.port}"
          cert_file: ${var.hsl_server.cert_file}
          key_file: ${var.hsl_server.key_file}
          max_queue_size: ${var.hsl_server.max_queue_size}
          buffer_size: ${var.hsl_server.buffer_size}
      apigee_server:
        enabled: ${var.apigee_server.enabled}
        message_end_token: ${var.apigee_server.message_end_token}
        server:
          endpoint: "0.0.0.0:${var.apigee_server.server.port}"
          cert_file: ${var.apigee_server.server.cert_file}
          key_file: ${var.apigee_server.server.key_file}
          max_queue_size: ${var.apigee_server.server.max_queue_size}
          buffer_size: ${var.apigee_server.server.buffer_size}
      http_reverse_proxy_enabled: ${var.http_reverse_proxy_enabled}
      tracer_auth:
        enabled: ${var.tracer_auth.enabled}
      pprof_server:
        enabled: ${var.pprof_server.enabled}
        endpoint: ${var.pprof_server.endpoint}
      remote:
        endpoint: ${var.endpoint}:${var.endpoint_port}
        secure: ${var.secure}
        ca_cert_file: ${local.remote_tls_ca_cert_file_name}
        client_cert_file: ${local.mtls_client_cert_file_name}
        client_key_file: ${local.mtls_client_key_file_name}
        grpc_max_call_recv_msg_size: ${var.remote_grpc_max_call_recv_msg_size}
        refresh_token_file: ${length(var.refresh_token_file) > 0 ? var.refresh_token_file : local.use_external_token_secret ? local.token_file_path : ""}
        max_tokens: ${var.remote_max_tokens}
      telemetry:
        service_name: traceable-agent
        propagation_formats:
          - B3
          - TRACECONTEXT
        reporting:
          endpoint: ${local.telemetry_reporting_endpoint}
          trace_reporter_type: "OTLP"
        metrics:
          enabled: ${var.metrics.enabled}
        internal_spans:
          enabled: ${var.internal_spans.enabled}
          logs_as_span_events: ${var.internal_spans.logs_as_span_events}
          logs_span_ticker_period: ${var.internal_spans.logs_span_ticker_period}
          logs_queue_size: ${var.internal_spans.logs_queue_size}
        data_capture: ${var.telemetry_data_capture}
      persistence_directory: ${local.persistence_directory}
    collector:
      enabled: ${var.collector_enabled}
      agent_manager_endpoint: "localhost:${var.server_port}"
      remote_configured_processors:
        ${indent(8, var.remote_configured_processors)}
      regex_match_cache:
        enabled: ${var.collector.regex_match_cache.enabled}
        size: ${var.collector.regex_match_cache.size}
      negative_match_cache:
        enabled: ${var.collector.negative_match_cache.enabled}
        body_params_cache_size: ${var.collector.negative_match_cache.body_params_cache_size}
        query_params_cache_size: ${var.collector.negative_match_cache.query_params_cache_size}
        headers_cache_size: ${var.collector.negative_match_cache.headers_cache_size}
        cookies_cache_size: ${var.collector.negative_match_cache.cookies_cache_size}
        others_cache_size: ${var.collector.negative_match_cache.others_cache_size}
      multipart_max_file_size: ${var.collector.multipart_max_file_size}
      skip_setting_grpc_logger: ${var.collector.skip_setting_grpc_logger}
      grpc_max_call_recv_msg_size: ${var.collector.grpc_max_call_recv_msg_size}
      config:
        extensions:
          traceable_tokenauth/server:
            enabled: ${var.tracer_auth.enabled}
          health_check:
            endpoint: 127.0.0.1:${var.collector.ports.health_check}
          ${indent(10, local.file_storage_extension)}

        connectors:
          traceable_pipeline_manager: {}

        receivers:
          ${indent(10, local.otlpreceiver_config)}

          # Collect own metrics
          prometheus:
            config:
              scrape_configs:
                - job_name: "otel-collector"
                  scrape_interval: 10s
                  static_configs:
                    - targets: ["127.0.0.1:${var.collector.ports.prometheus_receiver}"]

          ${indent(10, local.zipkinreceiver_config)}

        processors:
          transform/environment:
            error_mode: ignore
          traceable_dataparser:
          traceable_attributes:
          traceable_metadata:
          traceable_modsec:
          traceable_dataclassification:
          ${indent(10, local.span_remover_processor_config)}
          ${indent(10, local.bare_span_converter_processor_config)}
          ${indent(10, local.ip_resolution_processor_config)}
          batch:
            timeout: ${var.collector.batch.timeout}
            send_batch_size: ${var.collector.batch.send_batch_size}
            send_batch_max_size: ${var.collector.batch.send_batch_max_size}
            ${indent(12, local.batch_processor_agent_token_config)}
          ${indent(10, var.protoprocessor)}
          ${indent(10, var.base64decoderprocessor)}
          ${indent(10, local.servicenamerprocessor_config)}
          ${indent(10, local.k8sprocessor_config)}
          ${indent(10, local.traces_buffering_processor_config)}
          ${indent(10, local.metric_remover_processor_config)}
          ${indent(10, local.additional_processor_config)}
          ${indent(10, local.filter_internal_spans_config)}
          ${indent(10, local.filter_external_spans_config)}

        exporters:
          otlp:
            ${indent(12, local.collector_exporter_otlp_compression)}
            ${indent(12, local.otlp_exporter_sending_queue)}
          ${indent(10, local.prometheus_exporter_config)}
          ${indent(10, var.collector.additional_exporters)}

        service:
          telemetry:
            resource: {}
            metrics:
              address: "127.0.0.1:${var.collector.ports.prometheus_receiver}"
          pipelines:
            traces/entry:
              receivers: ${local.collector_traces_receivers}
              processors:
                [
                  transform/environment,
                  filter/external_spans,
                ]
              exporters: [traceable_pipeline_manager]
            traces:
              receivers: [traceable_pipeline_manager]
              processors: ${local.collector_processors}
              exporters: ${var.collector.service.pipelines.traces.exporters}
            traces/internal_spans:
              receivers: ${local.collector_traces_receivers}
              processors: ${local.collector_internal_spans_processors}
              exporters: ${var.collector.service.pipelines.traces.exporters}

            metrics:
              receivers: ${local.collector_metrics_receivers}
              processors: [transform/environment, traceable_metricremover, batch]
              exporters: ${var.collector.service.pipelines.metrics.exporters}

            ${indent(12, var.collector.additional_pipelines)}

          extensions: ${local.otlp_collector_extensions}
    agent_manager:
      enabled: ${var.agent_manager_enabled}
    ext_cap:
      enabled: ${var.ext_cap_enabled}
      service_name: ${var.ext_cap_service_name}
      max_body_size: ${var.max_body_size}
      max_span_depth: ${var.max_span_depth}
      timeout_ms: ${var.ext_cap_timeout_ms}
      ${indent(6, local.allowed_content_types)}
      blocking_config:
        enabled: ${local.blocking_enabled}
        modsecurity:
          enabled: ${var.modsecurity_enabled}
        evaluate_body: ${var.evaluate_body}
        skip_client_spans: ${var.ext_cap_blocking_skip_client_spans}
        skip_internal_request: ${var.skip_internal_request}
        response_status_code: ${var.blocking_status_code}
        response_message: ${var.blocking_message}
        region_blocking:
          enabled: ${var.region_blocking_enabled}
        edge_decision_service:
          enabled: ${var.ext_cap_edge_decision_service.enabled}
          endpoint: ${var.ext_cap_edge_decision_service.endpoint}
          timeout_ms: ${var.ext_cap_edge_decision_service.timeout_ms}
          ${indent(10, local.edge_decision_svc_include_regexes)}
          ${indent(10, local.edge_decision_svc_exclude_regexes)}
        evaluate_eds_first: ${var.ext_cap_evaluate_eds_first}
      remote_config:
        enabled: ${var.remote_config_enabled}
        endpoint: "localhost:${var.server_port}"
        poll_period_seconds: ${var.remote_config_poll_period}
        grpc_max_call_recv_msg_size: ${var.remote_config_grpc_max_call_recv_msg_size}
      sampling:
        enabled: ${var.sampling_enabled}
      logging:
        log_mode: LOG_MODE_STDOUT
        log_level: ${var.log_level_internal}
      metrics_config:
        enabled: ${var.ext_cap_metrics_config.enabled}
        max_queue_size: ${var.ext_cap_metrics_config.max_queue_size}
        endpoint_config:
          enabled: ${var.ext_cap_metrics_config.endpoint_config.enabled}
          max_endpoints: ${var.ext_cap_metrics_config.endpoint_config.max_endpoints}
          logging:
            enabled: ${var.ext_cap_metrics_config.endpoint_config.logging.enabled}
            frequency: ${var.ext_cap_metrics_config.endpoint_config.logging.frequency}
        logging:
          enabled: ${var.ext_cap_metrics_config.logging.enabled}
          frequency: ${var.ext_cap_metrics_config.logging.frequency}
        exporter:
          enabled: ${var.ext_cap_metrics_config.exporter.enabled}
          export_interval_ms: ${var.ext_cap_metrics_config.exporter.export_interval_ms}
          export_timeout_ms: ${var.ext_cap_metrics_config.exporter.export_timeout_ms}
      mirror:
        enabled: ${local.mirroring_enabled}
        sock_addr: "${var.daemon_set_mirroring.sock_addr_volume_path}/eve.json"
        max_buffer_size: ${var.daemon_set_mirroring.max_buffer_size}
        io_timeout: ${var.daemon_set_mirroring.io_timeout}
        background_stats_wait: ${var.daemon_set_mirroring.background_stats_wait}
        max_queue_depth: ${var.daemon_set_mirroring.max_queue_depth}
        pod_mirroring_enabled: ${local.pod_mirroring_enabled}
        daemon_set_mirroring_enabled: ${local.daemon_set_mirroring}
        mirror_all_namespaces: ${local.daemon_set_mirror_all_namespaces}
        ${indent(8, local.daemon_set_match_selectors)}
        ${indent(8, local.daemon_set_match_selectors_egress)}
        ${indent(8, local.daemon_set_match_selectors_ingress_and_egress)}
        ${indent(8, local.pod_mirroring_match_selectors)}
        ${indent(8, local.pod_mirroring_match_selectors_egress)}
        ${indent(8, local.pod_mirroring_match_selectors_ingress_and_egress)}
      ext_proc:
        request_body_mode: ${var.ext_proc.request_body_mode}
        response_body_mode: ${var.ext_proc.response_body_mode}
        websocket_parser_config:
          enabled: ${var.ext_proc.websocket_parser_config.enabled}
      auth:
        enabled: ${var.ext_cap_auth.enabled}
      bot_service:
        enabled: ${var.ext_cap_bot_service.enabled}
        endpoint: ${var.ext_cap_bot_service.endpoint}
        timeout_ms: ${var.ext_cap_bot_service.timeout_ms}
        ${indent(8, local.bot_svc_include_path_prefixes)}
      parser_config:
        max_body_size: ${var.ext_cap_parser_config.max_body_size}
        graphql:
          enabled: ${var.ext_cap_parser_config.graphql.enabled}
    injector:
      enabled: ${var.injector_enabled}
      k8s_incluster_client: true
      regcred_template: "/conf/injector/templates/regcred-secrets.tmpl.yaml"
      container_resources_template: "/conf/injector/templates/resources.tmpl.yaml"
      telemetry:
        ${indent(8, local.injector_propagation_formats)}
        reporting:
          endpoint: "agent.${var.namespace}:${local.injector_reporting_endpoint_port}"
          trace_reporter_type: ${var.injector.trace_reporter_type}
          enable_grpc_loadbalancing: ${var.injector.enable_grpc_loadbalancing}
        ${indent(8, local.injector_capture_content_type)}
      max_body_size: ${var.max_body_size}
      ${indent(6, local.allowed_content_types)}
      blocking_config:
        enabled: ${var.injector.blocking_config.enabled}
        modsecurity:
          enabled: ${var.injector.blocking_config.modsecurity.enabled}
        evaluate_body: ${var.injector.blocking_config.evaluate_body}
        skip_internal_request: ${var.injector.blocking_config.skip_internal_request}
        response_status_code: ${var.injector.blocking_config.blocking_status_code}
        response_message: '${var.injector.blocking_config.blocking_message}'
        response_content_type: ${var.injector.blocking_config.blocking_content_type}
        region_blocking:
          enabled: ${var.injector.blocking_config.region_blocking.enabled}
        edge_decision_service:
          enabled: ${var.injector.blocking_config.edge_decision_service.enabled}
          endpoint: ${var.injector.blocking_config.edge_decision_service.endpoint}
          timeoutMs: ${var.injector.blocking_config.edge_decision_service.timeout_ms}
          ${indent(10, local.injector_edge_decision_svc_include_regexes)}
          ${indent(10, local.injector_edge_decision_svc_exclude_regexes)}
        evaluate_eds_first: ${var.injector.blocking_config.evaluate_eds_first}
      remote_config:
        enabled: ${var.injector.remote_config.enabled}
        endpoint: "agent.${var.namespace}:${local.injector_remote_config_endpoint_port}"
        poll_period_seconds: ${var.injector.remote_config.poll_period_seconds}
        grpc_max_call_recv_msg_size: ${var.injector.remote_config.grpc_max_call_recv_msg_size}
      debug_log: ${var.injector.debug_log}
      sampling:
        enabled: ${var.injector.sampling.enabled}
      log_level: ${var.injector.log_level}
      metrics_config:
        enabled: ${var.injector.metrics_config.enabled}
        max_queue_size: ${var.injector.metrics_config.max_queue_size}
        endpoint_config:
          enabled: ${var.injector.metrics_config.endpoint_config.enabled}
          max_endpoints: ${var.injector.metrics_config.endpoint_config.max_endpoints}
          logging:
            enabled: ${var.injector.metrics_config.endpoint_config.logging.enabled}
            frequency: ${var.injector.metrics_config.endpoint_config.logging.frequency}
        logging:
          enabled: ${var.injector.metrics_config.logging.enabled}
          frequency: ${var.injector.metrics_config.logging.frequency}
        exporter:
          enabled: ${var.injector.metrics_config.exporter.enabled}
          export_interval_ms: ${var.injector.metrics_config.exporter.export_interval_ms}
          export_timeout_ms: ${var.injector.metrics_config.exporter.export_timeout_ms}
      bot_service:
        enabled: ${var.injector.bot_service.enabled}
        endpoint: ${var.injector.bot_service.endpoint}
        timeout_ms: ${var.injector.bot_service.timeout_ms}
        ${indent(8, local.injector_bot_svc_include_prefixes)}
      parser_config:
        max_body_size: ${var.injector.parser_config.max_body_size}
        graphql:
          enabled: ${var.injector.parser_config.graphql.enabled}
      images_repository: ${local.injector_images_repository}
      tls_enabled: ${var.tls_enabled}
      servicename_with_namespace: ${var.injector.servicename_with_namespace}
      pprof_server:
        enabled: ${var.injector.pprof_server.enabled}
        endpoint: ${var.injector.pprof_server.endpoint}
      java:
        image_version: ${var.injector.java.image_version}
        image_name: ${var.injector.java.image_name}
        init_container_resources:
          limits:
            cpu: "${var.injector.java.init_container_resources.limits.cpu}"
            memory: "${var.injector.java.init_container_resources.limits.memory}"
          requests:
            cpu: "${var.injector.java.init_container_resources.requests.cpu}"
            memory: "${var.injector.java.init_container_resources.requests.memory}"
        ${indent(8, local.java_match_selectors)}
        filter_impl: ${var.injector.java.filter_impl}
      nginx:
        image_version: ${local.injector_nginx_image_version}
        init_container_resources:
          limits:
            cpu: "${var.injector.nginx.init_container_resources.limits.cpu}"
            memory: "${var.injector.nginx.init_container_resources.limits.memory}"
          requests:
            cpu: "${var.injector.nginx.init_container_resources.requests.cpu}"
            memory: "${var.injector.nginx.init_container_resources.requests.memory}"
        ${indent(8, local.nginx_match_selectors)}
        config_map_name: ${var.injector.nginx.config_map_name}
        container_name: ${var.injector.nginx.container_name}
      nginx_cpp:
        image_version: ${var.injector.nginx_cpp.image_version}
        agent_version: ${var.injector.nginx_cpp.agent_version}
        image_name: ${var.injector.nginx_cpp.image_name}
        config_map_name: ${var.injector.nginx_cpp.config_map_name}
        container_name: ${var.injector.nginx_cpp.container_name}
        init_container_resources:
          limits:
            cpu: "${var.injector.nginx_cpp.init_container_resources.limits.cpu}"
            memory: "${var.injector.nginx_cpp.init_container_resources.limits.memory}"
          requests:
            cpu: "${var.injector.nginx_cpp.init_container_resources.requests.cpu}"
            memory: "${var.injector.nginx_cpp.init_container_resources.requests.memory}"
        ${indent(8, local.nginx_cpp_match_selectors)}
        config:
          service_name: "${var.injector.nginx_cpp.config.service_name}"
          collector_host: "agent.${var.namespace}"
          collector_port: ${local.injector_nginx_cpp_reporting_endpoint_port}
          config_endpoint: "agent.${var.namespace}:${local.injector_remote_config_endpoint_port}"
          config_polling_period: ${var.injector.nginx_cpp.config.config_polling_period_seconds}
          blocking: "${var.injector.nginx_cpp.config.blocking}"
          blocking_status_code: ${var.injector.nginx_cpp.config.blocking_status_code}
          blocking_skip_internal_request: "${var.injector.nginx_cpp.config.blocking_skip_internal_request}"
          sampling: "${var.injector.nginx_cpp.config.sampling}"
          log_mode: "LOG_MODE_STDOUT"
          log_level: "${var.injector.nginx_cpp.config.log_level}"
          metrics: "${var.injector.nginx_cpp.config.metrics}"
          metrics_log: "${var.injector.nginx_cpp.config.metrics_log}"
          metrics_log_frequency: "${var.injector.nginx_cpp.config.metrics_log_frequency}"
          endpoint_metrics: "${var.injector.nginx_cpp.config.endpoint_metrics}"
          endpoint_metrics_log: "${var.injector.nginx_cpp.config.endpoint_metrics_log}"
          endpoint_metrics_log_frequency: "${var.injector.nginx_cpp.config.endpoint_metrics_log_frequency}"
          endpoint_metrics_max_endpoints: ${var.injector.nginx_cpp.config.endpoint_metrics_max_endpoints}
          ${indent(10, local.nginx_capture_content_types)}

      tme:
        image_version: ${local.injector_tme_image_version}
        image_name: ${var.injector.tme.image_name}
        container_template: "/conf/injector/templates/tme-container.tmpl.yaml"
        config_template: "/conf/injector/templates/tme-config.tmpl.yaml"
        rest_idle_timeout: ${var.injector_tme_rest_server_idle_timeout}
        rest_disable_keep_alive: ${var.injector_tme_rest_server_disable_keep_alive}
        resources:
          limits:
            cpu: "${var.injector.tme.resources.limits.cpu}"
            memory: "${var.injector.tme.resources.limits.memory}"
          requests:
            cpu: "${var.injector.tme.resources.requests.cpu}"
            memory: "${var.injector.tme.resources.requests.memory}"
        disable_outbound_port_exclude_anno: ${var.injector.tme.disable_outbound_port_exclude_anno}
        ${indent(8, local.tme_match_selectors)}
      mirror:
        image_version: ${var.injector.mirror.image_version}
        image_name: ${var.injector.mirror.image_name}
        resources:
          limits:
            cpu: "${var.injector.mirror.resources.limits.cpu}"
            memory: "${var.injector.mirror.resources.limits.memory}"
          requests:
            cpu: "${var.injector.mirror.resources.requests.cpu}"
            memory: "${var.injector.mirror.resources.requests.memory}"
        mtu: ${var.injector.mirror.mtu}
        ${indent(8, local.mirror_match_selectors)}
        ${indent(8, local.mirror_match_selectors_egress)}
        ${indent(8, local.mirror_match_selectors_ingress_and_egress)}
      haproxy:
        image_version: ${local.injector_haproxy_image_version}
        image_name: ${var.injector.haproxy.image_name}
        init_container_resources:
          limits:
            cpu: "${var.injector.haproxy.init_container_resources.limits.cpu}"
            memory: "${var.injector.haproxy.init_container_resources.limits.memory}"
          requests:
            cpu: "${var.injector.haproxy.init_container_resources.requests.cpu}"
            memory: "${var.injector.haproxy.init_container_resources.requests.memory}"
        port: ${var.injector.haproxy.port}
        request_capture_message_name: "traceableai-reqcap"
        response_capture_message_name: "traceableai-rescap"
        snippets_path: "/conf/injector/templates/haproxy"
        ${indent(8, local.haproxy_match_selectors)}
        close_server_on_connection_error: ${var.injector.haproxy.close_server_on_connection_error}
      wasm:
        image_version: ${local.injector_wasm_image_version}
        image_name: ${var.injector.wasm.image_name}
      ext_proc:
        request_body_mode: ${var.injector.ext_proc.request_body_processing_mode}
        response_body_mode: ${var.injector.ext_proc.response_body_processing_mode}
        websocket_parser_config:
          enabled: ${var.injector.ext_proc.websocket_parser_config.enabled}
      extension_service:
        image_version: ${var.extension_service.image_version}
        image_name: ${var.extension_service.image_name}
        port: ${var.extension_service.port}
        resources:
          limits:
              cpu: "${var.extension_service.resources.limits.cpu}"
              memory: "${var.extension_service.resources.limits.memory}"
          requests:
              cpu: "${var.extension_service.resources.requests.cpu}"
              memory: "${var.extension_service.resources.requests.memory}"
        ${indent(8, local.extension_service_match_selectors)}
    EOF
  }
}
