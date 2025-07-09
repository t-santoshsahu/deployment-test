# The api token required to communicate with the api.traceable.ai platform.
# See https://docs.traceable.ai on how to obtain an access token
variable "token" {
  type    = string
  default = ""
}

# k8s provider cluster config info
variable "kubernetes_config_path" {
  type    = string
  default = "~/.kube/config"
}

# Configs for services enabled
variable "collector_enabled" {
  type    = bool
  default = true
}

variable "agent_manager_enabled" {
  type    = bool
  default = true
}

variable "ext_cap_enabled" {
  type    = bool
  default = true
}

variable "injector_enabled" {
  type    = bool
  default = true
}

variable "log_level" {
  type    = string
  default = "info"
}

variable "log_encoding" {
  type    = string
  default = "json"
}

variable "log_level_internal" {
  type    = string
  default = "LOG_LEVEL_INFO"

  validation {
    condition     = contains(["LOG_LEVEL_TRACE", "LOG_LEVEL_DEBUG", "LOG_LEVEL_INFO", "LOG_LEVEL_WARN", "LOG_LEVEL_ERROR", "LOG_LEVEL_CRITICAL"], var.log_level_internal)
    error_message = "Variable log_level_internal must be one of LOG_LEVEL_TRACE, LOG_LEVEL_DEBUG, LOG_LEVEL_INFO, LOG_LEVEL_WARN, LOG_LEVEL_ERROR, or LOG_LEVEL_CRITICAL."
  }
}

# Environment name attribute
variable "environment" {
  type    = string
  default = ""
}

# Cluster name
variable "cluster_name" {
  type    = string
  default = ""
}

# Persistence Volume Claim name
# When this is set, the pvc is expected to be in the same namespace as traceable-agent.
variable "persistence_pvc_name" {
  type    = string
  default = ""
}

# Modsecurity enabled
variable "modsecurity_enabled" {
  type    = bool
  default = true
}

# Body evaluation enabled
variable "evaluate_body" {
  type    = bool
  default = true
}

# Skip blocking evaluation for internal request
variable "skip_internal_request" {
  type    = bool
  default = true
}

variable "blocking_status_code" {
  type    = number
  default = 403
}

variable "blocking_message" {
  type    = string
  default = "Access Forbidden"
}

# Region Blocking enabled
variable "region_blocking_enabled" {
  type    = bool
  default = true
}

# Remote config enabled
variable "remote_config_enabled" {
  type    = bool
  default = true
}

# Remote config poll period
variable "remote_config_poll_period" {
  type    = number
  default = 30
}

# Remote config grpc_max_call_recv_msg_size
variable "remote_config_grpc_max_call_recv_msg_size" {
  type    = number
  default = 33554432
}

# maximum number of agent tokens tracked by the agent, for internal use only
variable "remote_max_tokens" {
  type    = number
  default = 1
}

# Namespace variables
variable "namespace" {
  type    = string
  default = "traceableai"
}

# Traceable.ai API endpoint
variable "endpoint" {
  type    = string
  default = "api.traceable.ai"
}

# Traceable.ai API port
variable "endpoint_port" {
  type    = number
  default = 443
}

variable "secure" {
  type    = bool
  default = true
}

# tls enabled
variable "tls_enabled" {
  type    = bool
  default = false
}

variable "tls_private_certificates_as_secret" {
  type = object({
    secret_name       = string
    root_ca_file_name = string
    cert_file_name    = string
    key_file_name     = string
  })
  default = {
    secret_name       = ""
    root_ca_file_name = ""
    cert_file_name    = ""
    key_file_name     = ""
  }
}

variable "tls_private_certificates_as_files" {
  type = object({
    root_ca_file_name = string
    cert_file_name    = string
    key_file_name     = string
  })
  default = {
    root_ca_file_name = ""
    cert_file_name    = ""
    key_file_name     = ""
  }
}

variable "tls_private_certificates_as_strings" {
  type = object({
    root_ca_b64 = string
    cert_b64    = string
    key_b64     = string
  })
  default = {
    root_ca_b64 = ""
    cert_b64    = ""
    key_b64     = ""
  }
}

# Custom CA cert for traceable-agent(TA) to platform connections.
#
# CA Bundle which is the base64 encoding of CA cert file contents.
variable "remote_ca_bundle" {
  type    = string
  default = ""
}

# CA as a secret in the same namespace as the TA deployment
variable "remote_ca_cert_secret" {
  type = object({
    secret_name       = string
    ca_cert_file_name = string
  })
  default = {
    secret_name       = ""
    ca_cert_file_name = ""
  }
}

# CA as a file injected into the TA container. This should be the absolute path to the file.
variable "remote_ca_cert_file" {
  type    = string
  default = ""
}

# Custom client cert & key for mTLS connections with platform
variable "remote_client_cert" {
  type    = string
  default = ""
}
variable "remote_client_key" {
  type    = string
  default = ""
}

# client cert & key if already in an available secret
variable "remote_client_cert_key_secret" {
  type = object({
    secret_name      = string
    client_cert_name = string
    client_key_name  = string
  })
  default = {
    secret_name      = ""
    client_cert_name = ""
    client_key_name  = ""
  }
}

# Path to file if attached from existing volume. This should be the absolute path to the file.
variable "remote_client_cert_file" {
  type    = string
  default = ""
}
variable "remote_client_key_file" {
  type    = string
  default = ""
}

# Max receive message size(bytes) for grpc channel
# 33554432 = 32 * 1024 * 1024 = 32MB
variable "remote_grpc_max_call_recv_msg_size" {
  type    = number
  default = 33554432
}

# Use rest_server as a http reverse proxy
variable "http_reverse_proxy_enabled" {
  type    = bool
  default = true
}

# Https proxy value. If using a proxy for outgoing traffic to the platform set this
# to the proxy endpoint(scheme, host and port if necessary eg. https://proxy.mycorp.com:8787).
variable "https_proxy" {
  type    = string
  default = ""
}

# http proxy value. In case the http proxy needs to be set but since TPA -> platform traffic we prefer
# https_proxy instead of http_proxy
variable "http_proxy" {
  type    = string
  default = ""
}

# no proxy value. Set this to exclude IPs and hosts from having the traffic to them routed via the http
# or https proxy. We exclude local traffic by default.
variable "no_proxy" {
  type    = string
  default = "localhost,127.0.0.1"
}

# Container cpu and memory resource allocation
variable "resources" {
  type = object({
    requests = map(string)
    limits   = map(string)
  })
  default = {
    limits = {
      cpu    = "1"
      memory = "2Gi"
    }
    requests = {
      cpu    = "200m"
      memory = "400Mi"
    }
  }
}

# Tolerations are configured on a pod to allowed it to be scheduled on nodes with the corresponding
# taints. See https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/
# Example tolerations config. Be sure to set the config fields you do not want set to null:
#
# tolerations = [
#   {
#     key                = "key1"
#     operator           = "Equal"
#     value              = "value1"
#     effect             = "NoSchedule"
#     toleration_seconds = null
#   },
#   {
#     key                = "key2"
#     operator           = "Equal"
#     value              = "value2"
#     effect             = "NoExecute"
#     toleration_seconds = 6000
#   }
# ]
#
variable "tolerations" {
  type = list(object({
    effect             = string
    key                = string
    operator           = string
    toleration_seconds = number
    value              = string
  }))
  default = []
}

# span remover processor config
variable "span_remover_processor" {
  type = map(list(map(string)))
  default = {
    "service_exclude_span_processing_rules" = []
  }
}

# span remover processor config
# It removes a span whose servicename belongs to one the services under the services config
# or whose attributes matches by key or by key and value as configured.
variable "bare_span_converter_processor" {
  type = map(list(string))
  default = {
    "header_prefixes"      = ["http.request.header.", "http.response.header.", "rpc.request.metadata.", "rpc.response.metadata."]
    "body_prefixes"        = ["http.request.body", "http.response.body", "rpc.request.body", "rpc.response.body"]
    "header_names_to_keep" = ["x-real-ip", "forwarded", "x-forwarded-for", "x-proxyuser-ip", ":authority", "grpc-status", ":status", ":path", "content-length", "content-type", "host", "user-agent"]
  }
}

variable "ip_resolution_processor" {
  type = map(any)
  default = {
    cache_duration_minutes         = 10
    cache_cleanup_interval_minutes = 10
    max_ip_queue_size              = 10000
    max_resolution_time_ms         = 1000
  }
}

variable "additional_trace_preprocessing_pipeline" {
  type    = list(string)
  default = []
}

variable "additional_trace_internal_span_processors" {
  type    = list(string)
  default = []
}

variable "protoprocessor" {
  type    = string
  default = <<EOF
traceable_protoprocessor:
  strip_encoded_attribute: true
EOF
}

variable "base64decoderprocessor" {
  type    = string
  default = <<EOF
traceable_base64decoderprocessor:
  strip_encoded_attribute: true
EOF
}

variable "traces_buffering_processor_enabled" {
  type    = bool
  default = true
}

variable "traces_buffering_processor" {
  type = object({
    buffer_capacity            = number
    no_of_workers              = number
    send_buffer_overflow_spans = bool
  })
  default = {
    buffer_capacity            = 10
    no_of_workers              = 0
    send_buffer_overflow_spans = false
  }
}

# metric remover processor config
variable "metric_remover_processor" {
  type = object({
    match_type = string
    names      = list(string)
  })
  default = {
    match_type = "regexp"
    names      = ["^http\\.server.*", "^http\\.client.*", "^rpc\\.server.*", "^rpc\\.client.*", ".*db.*", ".*jvm.*", ".*kafka.*", "processedSpans", "queueSize", "^otlp.*"]
  }
}

variable "filter_internal_spans_processor" {
  type = object({
    error_mode = string
    traces = object({
      span = list(string)
    })
  })
  default = {
    error_mode = "ignore"
    traces = {
      span = ["resource.attributes[\"deployment.environment\"] != \"traceableai-internal\""]
    }
  }
}

variable "filter_external_spans_processor" {
  type = object({
    error_mode = string
    traces = object({
      span = list(string)
    })
  })
  default = {
    error_mode = "ignore"
    traces = {
      span = ["resource.attributes[\"deployment.environment\"] == \"traceableai-internal\""]
    }
  }
}

# Blocking enabled
variable "blocking_enabled" {
  type    = bool
  default = true
}

# Sampling enabled
variable "sampling_enabled" {
  type    = bool
  default = true
}

# Collector processors which get configuration from remote
variable "remote_configured_processors" {
  type    = string
  default = <<EOF
- "traceable_dataparser"
- "traceable_attributes"
- "traceable_modsec"
- "traceable_dataclassification"
- "traceable_spanremover"
EOF
}

# The image_name should not include the repository.
# It is not needed when downloading from dockerhub.
variable "image_name" {
  type    = string
  default = "traceable-agent"
}

# When creating a release, this value will be updated
variable "image_version" {
  type    = string
  default = "1.58.0"
}

variable "image_pull_policy" {
  type    = string
  default = "IfNotPresent"
}

# Credentials for the docker images
variable "image_credentials" {
  type = map(string)
  default = {
    "registry"        = "docker.io"
    "registry_suffix" = "traceableai"
    "username"        = ""
    "password"        = ""
  }
}

# Custom image pull secret name. Should exist in the same namespace that traceable-agent deployment will
# run in.
variable "image_pull_secret_name" {
  type    = string
  default = ""
}

# Externally defined token secret
variable "external_token_secret" {
  type = map(string)
  default = {
    "name" = ""
    "key"  = ""
  }
}

variable "refresh_token_file" {
  type    = string
  default = ""
}

variable "refresh_token_gcp_secret_project" {
  type    = string
  default = ""
}

variable "refresh_token_gcp_secret_name" {
  type    = string
  default = ""
}

variable "gke_service_account" {
  type    = string
  default = ""
}

variable "additional_annotations" {
  type = map(string)
  default = {
    "data-ingest.dynatrace.com/inject" = "false"
    "dynakube.dynatrace.com/inject"    = "false"
    "oneagent.dynatrace.com/inject"    = "false"
    "dynatrace.com/inject"             = "false"
  }
}

# Whether to run as a daemonset or deployment
# Default is deployment
variable "run_as_daemon_set" {
  type    = bool
  default = false
}

variable "labels" {
  type    = map(string)
  default = {}
}

variable "service_type" {
  type    = string
  default = "ClusterIP"
}

variable "load_balancer_ip" {
  type    = string
  default = ""
}

variable "service_labels" {
  type    = map(string)
  default = {}
}

variable "service_annotations" {
  type    = map(string)
  default = {}
}

variable "load_balancer_https_agent_service" {
  type = object({
    enabled     = bool
    port        = number
    target_port = number
  })
  default = {
    enabled     = false
    port        = 0
    target_port = 0
  }
}

variable "service_external_traffic_policy" {
  type    = string
  default = ""
}

variable "ingress" {
  type = object({
    enabled            = bool
    domain             = string
    ingress_class_name = string
    http = object({
      annotations = map(string)
    })
    grpc = object({
      annotations = map(string)
    })
  })

  default = {
    enabled            = false
    domain             = ""
    ingress_class_name = ""
    http = {
      annotations = {}
    }
    grpc = {
      annotations = {}
    }
  }
}

# Traceable agent server port
variable "server_port" {
  type    = string
  default = 5441
}

variable "server_port_max_connection_age" {
  type    = string
  default = "9223372036854775807ns"
}

variable "rest_server_port" {
  type    = string
  default = 5442
}

variable "rest_server_idle_timeout" {
  type    = number
  default = 60
}

variable "rest_server_disable_keep_alive" {
  type    = bool
  default = false
}

variable "tls_server_idle_timeout" {
  type    = number
  default = 60
}

variable "tls_server_disable_keep_alive" {
  type    = bool
  default = false
}

variable "injector_tme_rest_server_idle_timeout" {
  type    = number
  default = 60
}

variable "injector_tme_rest_server_disable_keep_alive" {
  type    = bool
  default = false
}

variable "injector_webhook_domain" {
  type    = string
  default = ""
}

variable "tls_server_port" {
  type    = string
  default = 5443
}

variable "single_service_mode" {
  type    = bool
  default = false
}

variable "rest_server_node_port" {
  type    = number
  default = 0
}

variable "tls_server_node_port" {
  type    = number
  default = 0
}

variable "ext_cap_service_name" {
  type    = string
  default = "ext_cap"
}

variable "telemetry_reporting_endpoint" {
  type    = string
  default = ""
}

# max body size to capture
variable "max_body_size" {
  type    = number
  default = 131072
}

# max spans level in a trace, 1 means only root span
variable "max_span_depth" {
  type    = number
  default = 2
}

# Timeout in milliseconds; set to 0 to disable the timeout.
variable "ext_cap_timeout_ms" {
  type    = number
  default = 0
}

# body types to process and capture
variable "allowed_content_types" {
  type    = list(string)
  default = ["json", "x-www-form-urlencoded", "xml", "graphql"]
}

variable "metrics" {
  type = object({
    enabled = bool
  })
  default = {
    enabled = true
  }
}

# Whether internal tracing should capture data
variable "telemetry_data_capture" {
  type    = bool
  default = false
}

# Internal spans config
variable "internal_spans" {
  type = object({
    enabled                 = bool
    logs_as_span_events     = bool
    logs_span_ticker_period = number
    logs_queue_size         = number
  })
  default = {
    enabled                 = true
    logs_as_span_events     = true
    logs_span_ticker_period = 5
    logs_queue_size         = 2048
  }
}

# OTLP Exporter Persistent Queue Enabled
variable "persistent_queue_enabled" {
  type    = bool
  default = true
}

variable "collector" {
  type = object({
    ports = object({
      opentelemetry       = string
      opentelemetry_http  = string
      zipkin              = string
      prometheus          = string
      prometheus_receiver = string
      health_check        = string
    })
    additional_processors = map(any)
    additional_exporters  = string
    additional_pipelines  = string
    service = object({
      pipelines = object({
        traces = object({
          exporters = string
        })
        metrics = object({
          exporters = string
        })
      })
    })
    batch = object({
      timeout             = string
      send_batch_size     = number
      send_batch_max_size = number
    })
    receivers = object({
      otlp = object({
        enabled               = bool
        max_recv_msg_size_mib = number
        max_connection_age    = string
      })
      zipkin = object({
        enabled = bool
      })
    })
    exporters = object({
      otlp = object({
        compression = string
      })
      prometheus = object({
        enabled = bool
      })
    })
    regex_match_cache = object({
      enabled = bool
      size    = number
    })
    negative_match_cache = object({
      enabled                 = bool
      body_params_cache_size  = number
      query_params_cache_size = number
      headers_cache_size      = number
      cookies_cache_size      = number
      others_cache_size       = number
    })
    multipart_max_file_size     = number
    skip_setting_grpc_logger    = bool
    grpc_max_call_recv_msg_size = number
  })
  default = {
    ports = {
      opentelemetry       = 4317
      opentelemetry_http  = 4318
      zipkin              = 9411
      prometheus          = 8889
      prometheus_receiver = 8888
      health_check        = 13133
    }
    additional_processors = {}
    additional_exporters  = ""
    additional_pipelines  = ""
    service = {
      pipelines = {
        traces = {
          exporters = "[otlp]"
        }
        metrics = {
          exporters = "[otlp]"
        }
      }
    }
    batch = {
      timeout             = "200ms"
      send_batch_size     = 8192
      send_batch_max_size = 10000
    }
    receivers = {
      otlp = {
        enabled               = true
        max_recv_msg_size_mib = 16
        max_connection_age    = "1m"
      }
      zipkin = {
        enabled = true
      }
    }
    exporters = {
      otlp = {
        compression = "gzip"
      }
      prometheus = {
        enabled = true
      }
    }
    regex_match_cache = {
      enabled = true
      size    = 500000
    }
    negative_match_cache = {
      enabled                 = true
      body_params_cache_size  = 2000000
      query_params_cache_size = 20000
      headers_cache_size      = 400000
      cookies_cache_size      = 400000
      others_cache_size       = 20000
    }
    multipart_max_file_size     = 2048
    skip_setting_grpc_logger    = true
    grpc_max_call_recv_msg_size = 33554432
  }
}

# Replica count for the deployment
variable "deployment_replica_count" {
  type    = number
  default = 1
}

# Whether to define cluster roles and bindings tied to the service account
variable "cluster_roles_enabled" {
  type    = bool
  default = true
}

# Enable if pod security policies are required
variable "pod_security_policies_enabled" {
  type    = bool
  default = false
}

variable "k8sprocessor_enabled" {
  type    = bool
  default = false
}

variable "servicenamerprocessor_enabled" {
  type    = bool
  default = false
}

# injector.ca_bundle is expected to be a base64 encoded string passed when using custom
# private tls certificates not generated based on the k8s api server certificates.
variable "injector" {
  type = object({
    failure_policy             = string
    trace_reporter_type        = string
    servicename_with_namespace = bool
    enable_grpc_loadbalancing  = bool
    blocking_config = object({
      enabled = bool
      modsecurity = object({
        enabled = bool
      })
      evaluate_body         = bool
      skip_internal_request = bool
      blocking_status_code  = number
      blocking_message      = string
      blocking_content_type = string
      region_blocking = object({
        enabled = bool
      })
      edge_decision_service = object({
        enabled              = bool
        endpoint             = string
        timeout_ms           = number
        include_path_regexes = list(string)
        exclude_path_regexes = list(string)
      })
      evaluate_eds_first = bool
    })
    pprof_server = object({
      enabled  = bool
      endpoint = string
    })
    remote_config = object({
      enabled                     = bool
      poll_period_seconds         = number
      grpc_max_call_recv_msg_size = number
    })
    debug_log = bool
    sampling = object({
      enabled = bool
    })
    log_level = string
    metrics_config = object({
      enabled        = bool
      max_queue_size = number
      endpoint_config = object({
        enabled       = bool
        max_endpoints = number
        logging = object({
          enabled   = bool
          frequency = string
        })
      })
      logging = object({
        enabled   = bool
        frequency = string
      })
      exporter = object({
        enabled            = bool
        export_interval_ms = number
        export_timeout_ms  = number
      })
    })
    bot_service = object({
      enabled               = bool
      endpoint              = string
      timeout_ms            = number
      include_path_prefixes = list(string)
    })
    parser_config = object({
      max_body_size = number
      graphql = object({
        enabled = bool
      })
    })
    propagation_formats  = list(string)
    capture_content_type = list(string)
    ca_bundle            = string
    java = object({
      image_version = string
      image_name    = string
      init_container_resources = object({
        limits   = map(string)
        requests = map(string)
      })
      match_selectors = list(map(list(string)))
      filter_impl     = string
    })
    nginx = object({
      image_version = string
      init_container_resources = object({
        limits   = map(string)
        requests = map(string)
      })
      match_selectors = list(map(list(string)))
      config_map_name = string
      container_name  = string
    })
    nginx_cpp = object({
      image_name      = string
      image_version   = string
      agent_version   = string
      config_map_name = string
      container_name  = string
      init_container_resources = object({
        limits   = map(string)
        requests = map(string)
      })
      match_selectors = list(map(list(string)))
      config = object({
        service_name                   = string
        config_polling_period_seconds  = number
        blocking                       = string
        blocking_status_code           = number
        blocking_skip_internal_request = string
        sampling                       = string
        log_level                      = string
        metrics                        = string
        metrics_log                    = string
        metrics_log_frequency          = string
        endpoint_metrics               = string
        endpoint_metrics_log           = string
        endpoint_metrics_log_frequency = string
        endpoint_metrics_max_endpoints = number
        capture_content_types          = list(string)
      })
    })
    tme = object({
      image_version = string
      image_name    = string
      resources = object({
        limits   = map(string)
        requests = map(string)
      })
      disable_outbound_port_exclude_anno = bool
      match_selectors                    = list(map(list(string)))
    })
    mirror = object({
      image_version = string
      image_name    = string
      resources = object({
        limits   = map(string)
        requests = map(string)
      })
      mtu                                = number
      match_selectors                    = list(map(list(string)))
      match_selectors_egress             = list(map(list(string)))
      match_selectors_ingress_and_egress = list(map(list(string)))
    })
    haproxy = object({
      image_version = string
      image_name    = string
      init_container_resources = object({
        limits   = map(string)
        requests = map(string)
      })
      port                             = number
      match_selectors                  = list(map(list(string)))
      close_server_on_connection_error = bool
    })
    wasm = object({
      image_version = string
      image_name    = string
    })
    ext_proc = object({
      request_body_processing_mode  = string
      response_body_processing_mode = string
      websocket_parser_config = object({
        enabled = bool
      })
    })
  })
  default = {
    failure_policy             = "Ignore"
    trace_reporter_type        = "OTLP"
    servicename_with_namespace = false
    enable_grpc_loadbalancing  = true
    blocking_config = {
      enabled = true
      modsecurity = {
        enabled = true
      }
      evaluate_body         = true
      skip_internal_request = true
      blocking_status_code  = 403
      blocking_message      = "Access Forbidden"
      blocking_content_type = ""
      region_blocking = {
        enabled = true
      }
      edge_decision_service = {
        enabled              = false
        endpoint             = "localhost:62060"
        timeout_ms           = 20
        include_path_regexes = []
        exclude_path_regexes = []
      }
      evaluate_eds_first = false
    }
    pprof_server = {
      enabled  = true
      endpoint = "127.0.0.1:1777"
    }
    remote_config = {
      enabled                     = true
      poll_period_seconds         = 30
      grpc_max_call_recv_msg_size = 33554432
    }
    debug_log = false
    sampling = {
      enabled = true
    }
    log_level = "info"
    metrics_config = {
      enabled        = false
      max_queue_size = 9216
      endpoint_config = {
        enabled       = false
        max_endpoints = 5000
        logging = {
          enabled   = false
          frequency = "30m"
        }
      }
      logging = {
        enabled   = false
        frequency = "30m"
      }
      exporter = {
        enabled            = false
        export_interval_ms = 60000
        export_timeout_ms  = 30000
      }
    }
    bot_service = {
      enabled               = false
      endpoint              = "http://localhost:63050/traceable/captcha/tpa_request"
      timeout_ms            = 30
      include_path_prefixes = ["/traceable/captcha"]
    }
    parser_config = {
      max_body_size = 131072 // 128KB
      graphql = {
        enabled = false
      }
    }
    propagation_formats  = ["TRACECONTEXT"]
    capture_content_type = ["json", "grpc", "x-www-form-urlencoded"]
    ca_bundle            = ""
    java = {
      image_version = "1.1.15"
      image_name    = "javaagent"
      init_container_resources = {
        limits = {
          cpu    = "200m"
          memory = "128Mi"
        }
        requests = {
          cpu    = "20m"
          memory = "64Mi"
        }
      }
      match_selectors = []
      filter_impl     = "LIBTRACEABLE"
    }
    nginx = {
      image_version = ""
      image_name    = "nginx-lua-plugin"
      init_container_resources = {
        limits = {
          cpu    = "200m"
          memory = "128Mi"
        }
        requests = {
          cpu    = "20m"
          memory = "64Mi"
        }
      }
      match_selectors = []
      config_map_name = ""
      container_name  = ""
    }
    nginx_cpp = {
      image_name      = "nginx-cpp-module"
      image_version   = ""
      agent_version   = "0.1.91"
      config_map_name = ""
      container_name  = ""
      init_container_resources = {
        limits = {
          cpu    = "200m"
          memory = "128Mi"
        }
        requests = {
          cpu    = "20m"
          memory = "64Mi"
        }
      }
      match_selectors = []
      config = {
        service_name                   = "ingress-nginx"
        config_polling_period_seconds  = 30
        blocking                       = "on"
        blocking_status_code           = 403
        blocking_skip_internal_request = "on"
        sampling                       = "on"
        log_level                      = "LOG_LEVEL_INFO"
        metrics                        = "off"
        metrics_log                    = "off"
        metrics_log_frequency          = "30m"
        endpoint_metrics               = "off"
        endpoint_metrics_log           = "off"
        endpoint_metrics_log_frequency = "30m"
        endpoint_metrics_max_endpoints = 5000
        capture_content_types          = ["json", "grpc", "xml"]
      }
    }
    tme = {
      image_version = ""
      image_name    = "traceable-agent"
      resources = {
        limits = {
          cpu    = "500m"
          memory = "512Mi"
        }
        requests = {
          cpu    = "100m"
          memory = "128Mi"
        }
      }
      disable_outbound_port_exclude_anno = false
      match_selectors                    = []
    }
    mirror = {
      image_version = "2.0.3"
      image_name    = "packet-forwarder"
      resources = {
        limits = {
          cpu    = "200m"
          memory = "256Mi"
        }
        requests = {
          cpu    = "100m"
          memory = "128Mi"
        }
      }
      mtu                                = 1500
      match_selectors                    = []
      match_selectors_egress             = []
      match_selectors_ingress_and_egress = []
    }
    haproxy = {
      image_version = ""
      image_name    = "haproxy-init"
      init_container_resources = {
        limits = {
          cpu    = "200m"
          memory = "128Mi"
        }
        requests = {
          cpu    = "20m"
          memory = "64Mi"
        }
      }
      port                             = 5444
      match_selectors                  = []
      close_server_on_connection_error = false
    }
    wasm = {
      image_version = ""
      image_name    = "wasm-init"
    }
    ext_proc = {
      request_body_processing_mode  = "BODY_SEND_MODE_BUFFERED_PARTIAL"
      response_body_processing_mode = "BODY_SEND_MODE_BUFFERED_PARTIAL"
      websocket_parser_config = {
        enabled = false
      }
    }
  }
  validation {
    condition = contains([
      "BODY_SEND_MODE_STREAMED",
      "BODY_SEND_MODE_BUFFERED",
      "BODY_SEND_MODE_BUFFERED_PARTIAL",
      "BODY_SEND_MODE_NONE"],
    var.injector.ext_proc.request_body_processing_mode)
    error_message = "Variable request_body_mode must be of {BODY_SEND_MODE_STREAMED, BODY_SEND_MODE_BUFFERED, BODY_SEND_MODE_BUFFERED_PARTIAL, BODY_SEND_MODE_NONE}"
  }

  validation {
    condition = contains([
      "BODY_SEND_MODE_STREAMED",
      "BODY_SEND_MODE_BUFFERED",
      "BODY_SEND_MODE_BUFFERED_PARTIAL",
      "BODY_SEND_MODE_NONE"],
    var.injector.ext_proc.response_body_processing_mode)
    error_message = "Variable response_body_mode must be of {BODY_SEND_MODE_STREAMED, BODY_SEND_MODE_BUFFERED, BODY_SEND_MODE_BUFFERED_PARTIAL, BODY_SEND_MODE_NONE}"
  }
}

variable "pod_mirroring_enabled" {
  type    = bool
  default = false
}

variable "daemon_set_mirroring_enabled" {
  type    = bool
  default = false
}

variable "daemon_set_mirror_all_namespaces" {
  type    = bool
  default = false
}

variable "ebpf_capture_enabled" {
  type    = bool
  default = false
}

variable "ebpf_log_level" {
  type    = string
  default = "info"

  validation {
    condition     = contains(["debug", "info", "warn", "error"], var.ebpf_log_level)
    error_message = "Variable ebpf_log_level must be one of {debug, info, warn, error}."
  }
}

variable "ebpf_run_as_privileged" {
  type    = bool
  default = false
}

variable "ebpf_se_linux_options_enabled" {
  type    = bool
  default = false
}

variable "ebpf_se_linux_options_role" {
  type    = string
  default = "system_r"
}

variable "ebpf_se_linux_options_type" {
  type    = string
  default = "spc_t"
}

variable "ebpf_se_linux_options_user" {
  type    = string
  default = "system_u"
}

variable "ebpf_unix_domain_socket_queue_size" {
  type    = number
  default = 10000
}

variable "ebpf_max_active_ret_probe" {
  type    = number
  default = 1
}

variable "ebpf_deploy_on_master" {
  type    = bool
  default = false
}

variable "ebpf_node_affinity_match_expressions" {
  type = set(object({
    match_expressions = set(object({
      key      = string,
      operator = string,
      values   = list(string)
    }))
  }))
  default = [
    {
      match_expressions = []
    }
  ]
}

variable "ebpf_custom_ssl_address" {
  type = list(object({
    binary_name       = string,
    SSL_write_address = list(string),
    SSL_read_address  = list(string),
    SSL_free_address  = list(string)
  }))
  default = []
}
variable "ebpf_tolerations" {
  type = list(object({
    key                = string,
    operator           = string,
    value              = string,
    effect             = string,
    toleration_seconds = number
  }))
  default = []
}

variable "ebpf_trace_reporter_type" {
  type    = string
  default = "OTLP"

  validation {
    condition     = contains(["OTLP", "ZIPKIN"], var.ebpf_trace_reporter_type)
    error_message = "Variable ebpf_trace_reporter_type must be either OTLP or ZIPKIN."
  }
}

variable "ebpf_node_selectors" {
  type    = map(string)
  default = {}
}

variable "node_selectors" {
  type    = map(string)
  default = {}
}

variable "node_affinity_match_expressions" {
  type = set(object({
    match_expressions = set(object({
      key      = string,
      operator = string,
      values   = list(string)
    }))
  }))
  default = [
    {
      match_expressions = []
    }
  ]
}

variable "pod_affinity" {
  type = set(object({
    topology_key = string,
    label_selector = set(object({
      match_expressions = set(object({
        key      = string,
        operator = string,
        values   = list(string)
      }))
    }))
  }))
  default = []
}

variable "pod_anti_affinity" {
  type = set(object({
    topology_key = string,
    label_selector = set(object({
      match_expressions = set(object({
        key      = string,
        operator = string,
        values   = list(string)
      }))
    }))
  }))
  default = []
}

variable "topology_spread_constraint" {
  type = set(object({
    label_selector = set(object({
      match_expressions = set(object({
        key      = string,
        operator = string,
        values   = list(string)
      }))
    })),
    match_label_keys     = optional(set(string)),
    max_skew             = optional(number),
    min_domains          = optional(number),
    node_affinity_policy = optional(string),
    node_taints_policy   = optional(string),
    topology_key         = optional(string),
    when_unsatisfiable   = optional(string)
  }))
  default = []
}

variable "pdb_min_available" {
  type    = string
  default = null
}

variable "pdb_max_unavailable" {
  type    = string
  default = null
}

variable "ebpf_environment" {
  type    = string
  default = ""
}

variable "ebpf_default_service_name" {
  type    = string
  default = "ebpf"
}

variable "ebpf_use_single_tracer" {
  type    = bool
  default = false
}

variable "ebpf_service_name_labels" {
  type    = list(string)
  default = []
}

variable "ebpf_pod_labels" {
  type    = list(string)
  default = []
}

variable "ebpf_pod_annotations" {
  type    = list(string)
  default = []
}

variable "ebpf_custom_span_attributes" {
  type        = map(string)
  default     = {}
  description = "Custom span attributes to be added to all spans captured by the eBPF agent"
}

variable "ebpf_libssl_prefixes" {
  type    = list(string)
  default = ["libssl.so", "libssl3.so"]
}

variable "ebpf_probe_event_queue_size" {
  type    = number
  default = 50000
}

variable "ebpf_exclude_processes" {
  type    = list(string)
  default = []
}

variable "ebpf_uprobe_attach_exclusion_rules" {
  type = list(object({
    exec_name               = string
    cmdline_args_match_type = string
    cmdline_args            = list(string)
  }))
  default = []
}

variable "ebpf_ssl_keylog_include_rules" {
  type = list(object({
    exec_name               = string
    cmdline_args_match_type = string
    cmdline_args            = list(string)
  }))
  default = []
}

variable "ebpf_use_custom_bsp" {
  type    = bool
  default = true
}

variable "ebpf_request_per_second_limit" {
  type    = number
  default = 1000
}

variable "ebpf_max_connection" {
  type    = number
  default = 10000
}

variable "daemon_set_mirroring" {
  type = object({
    resources = object({
      limits   = map(string)
      requests = map(string)
    })
    sock_addr_volume_path              = string
    max_buffer_size                    = number
    io_timeout                         = number
    background_stats_wait              = number
    max_queue_depth                    = number
    match_selectors                    = list(map(list(string)))
    match_selectors_egress             = list(map(list(string)))
    match_selectors_ingress_and_egress = list(map(list(string)))
  })
  default = {
    resources = {
      limits = {
        cpu    = "500m"
        memory = "1536Mi"
      }
      requests = {
        cpu    = "100m"
        memory = "128Mi"
      }
    }
    sock_addr_volume_path              = "/var/log/sock"
    max_buffer_size                    = 524288
    io_timeout                         = 60
    background_stats_wait              = 300
    max_queue_depth                    = 5000
    match_selectors                    = []
    match_selectors_egress             = []
    match_selectors_ingress_and_egress = []
  }
}

variable "ebpf_watch_match_selectors" {
  type = object({
    enabled              = bool
    pods_selectors       = map(list(string))
    namespaces_selectors = map(list(string))
  })
  default = {
    enabled              = true
    pods_selectors       = {}
    namespaces_selectors = {}
  }
}

variable "ebpf_btf_downloads_path" {
  type    = string
  default = "/etc/traceable/ebpf-tracer/btf/downloads"
}

variable "suricata_version" {
  type    = string
  default = ""
}

variable "suricata_image_name" {
  type    = string
  default = "suricata"
}

variable "ebpf_tracer_version" {
  type    = string
  default = "1.24.0"
}


variable "ebpf_tracer_image_name" {
  type    = string
  default = "ebpf-tracer"
}

variable "autoscaling" {
  type = object({
    enabled                   = bool
    min_replicas              = number
    max_replicas              = number
    target_memory_utilization = number
    target_cpu_utilization    = number
  })
  default = {
    enabled                   = true
    min_replicas              = 1
    max_replicas              = 1
    target_memory_utilization = 80
    target_cpu_utilization    = 80
  }
}

variable "ebpf_allowed_capabilities" {
  type    = list(string)
  default = ["IPC_LOCK", "SYS_ADMIN", "SYS_CHROOT", "SYS_RESOURCE", "SYS_PTRACE", "SETFCAP"]
}

variable "injector_allowed_capabilities" {
  type    = list(string)
  default = ["NET_ADMIN", "NET_RAW"]
}

variable "extension_service" {
  type = object({
    image_version       = string
    image_name          = string
    run_with_deployment = bool
    port                = number
    resources = object({
      limits   = map(string)
      requests = map(string)
    })
    match_selectors = list(map(list(string)))
  })
  default = {
    image_version       = "1.0.0"
    image_name          = "extension-service"
    run_with_deployment = false
    port                = 6001
    resources = {
      limits = {
        cpu    = "500m"
        memory = "512Mi"
      }
      requests = {
        cpu    = "100m"
        memory = "128Mi"
      }
    }
    match_selectors = []
  }
}

variable "ebpf_http2_capture_enabled" {
  type    = bool
  default = false
}

variable "ebpf_metrics_enabled" {
  type    = bool
  default = true
}

variable "ebpf_enable_java_tls_capture" {
  type    = bool
  default = false
}

variable "ebpf_enable_pprof_http" {
  type    = bool
  default = true
}

variable "ebpf_enable_tracepoints" {
  type    = bool
  default = false
}

variable "ebpf_pprof_port" {
  type    = number
  default = 1778
}

variable "ebpf_proc_fs_scan_period_in_sec" {
  type    = number
  default = 60
}

variable "ebpf_logging" {
  type = object({
    level              = string
    encoding           = string
    error_output_paths = list(string)
  })

  default = {
    level              = null
    encoding           = "json"
    error_output_paths = ["stdout"]
  }
}

variable "tpa_pod_security_context" {
  type = object({
    enabled                = bool
    fs_group               = string
    fs_group_change_policy = string
    run_as_group           = string
    run_as_non_root        = bool
    run_as_user            = string
    se_linux_options = object({
      level = string
      role  = string
      type  = string
      user  = string
    })
    seccomp_profile = object({
      localhost_profile = string
      type              = string
    })
    supplemental_groups = set(number)
    sysctl = object({
      name  = string
      value = string
    })
    windows_options = object({
      gmsa_credential_spec      = string
      gmsa_credential_spec_name = string
      host_process              = bool
      run_as_username           = string
    })
  })

  default = {
    enabled                = false
    fs_group               = null
    fs_group_change_policy = null
    run_as_group           = null
    run_as_non_root        = null
    run_as_user            = null
    se_linux_options = {
      level = null
      role  = null
      type  = null
      user  = null
    }
    seccomp_profile = {
      localhost_profile = null
      type              = null
    }
    supplemental_groups = []
    sysctl = {
      name  = null
      value = null
    }
    windows_options = {
      gmsa_credential_spec      = null
      gmsa_credential_spec_name = null
      host_process              = null
      run_as_username           = null
    }
  }
}

variable "security_context" {
  type = object({
    enabled                    = bool
    allow_privilege_escalation = bool
    capabilities = object({
      add  = list(string)
      drop = list(string)
    })
    privileged                = bool
    read_only_root_filesystem = bool
    run_as_group              = string
    run_as_non_root           = bool
    run_as_user               = string
    se_linux_options = object({
      level = string
      role  = string
      type  = string
      user  = string
    })
    seccomp_profile = object({
      localhost_profile = string
      type              = string
    })
  })

  default = {
    enabled                    = true
    allow_privilege_escalation = null
    capabilities = {
      add  = null
      drop = null
    }
    privileged                = null
    read_only_root_filesystem = null
    run_as_group              = null
    run_as_non_root           = null
    run_as_user               = null
    se_linux_options = {
      level = null
      role  = null
      type  = null
      user  = null
    }
    seccomp_profile = {
      localhost_profile = null
      type              = null
    }
  }
}

variable "ebpf_enable_go_memory_limit" {
  type    = bool
  default = true
}

variable "ebpf_default_rate_limit_config" {
  type = object({
    enabled                 = bool
    max_count_global        = number
    max_count_per_endpoint  = number
    refresh_period          = string
    value_expiration_period = string
    span_type               = string
  })

  default = {
    enabled                 = false
    max_count_global        = 0
    max_count_per_endpoint  = 0
    refresh_period          = "1m"
    value_expiration_period = "168h"
    span_type               = "SPAN_TYPE_NO_SPAN"
  }

  validation {
    condition = contains([
      "SPAN_TYPE_NO_SPAN",
      "SPAN_TYPE_BARE_SPAN",
      "SPAN_TYPE_FULL_SPAN"],
    var.ebpf_default_rate_limit_config.span_type)
    error_message = "Variable span_type must be one of {SPAN_TYPE_NO_SPAN, SPAN_TYPE_BARE_SPAN, SPAN_TYPE_FULL_SPAN}."
  }
}

variable "ebpf_filter_log_level" {
  type    = string
  default = "LOG_LEVEL_INFO"
}

variable "ebpf_filter_metrics_config" {
  type = object({
    enabled = bool
    endpoint_config = object({
      enabled       = bool
      max_endpoints = number
      logging = object({
        enabled   = bool
        frequency = string
      })
    })
    logging = object({
      enabled   = bool
      frequency = string
    })
  })

  default = {
    enabled = false
    endpoint_config = {
      enabled       = false
      max_endpoints = 5000
      logging = {
        enabled   = false
        frequency = "30m"
      }
    }
    logging = {
      enabled   = false
      frequency = "30m"
    }
  }
}

variable "ext_proc" {
  type = object({
    request_body_mode  = string
    response_body_mode = string
    websocket_parser_config = object({
      enabled = bool
    })
  })
  default = {
    request_body_mode  = "BODY_SEND_MODE_BUFFERED_PARTIAL"
    response_body_mode = "BODY_SEND_MODE_BUFFERED_PARTIAL"
    websocket_parser_config = {
      enabled = false
    }
  }

  validation {
    condition = contains([
      "BODY_SEND_MODE_STREAMED",
      "BODY_SEND_MODE_BUFFERED",
      "BODY_SEND_MODE_BUFFERED_PARTIAL",
      "BODY_SEND_MODE_NONE"],
    var.ext_proc.request_body_mode)
    error_message = "Variable request_body_mode must be of {BODY_SEND_MODE_STREAMED, BODY_SEND_MODE_BUFFERED, BODY_SEND_MODE_BUFFERED_PARTIAL, BODY_SEND_MODE_NONE}"
  }

  validation {
    condition = contains([
      "BODY_SEND_MODE_STREAMED",
      "BODY_SEND_MODE_BUFFERED",
      "BODY_SEND_MODE_BUFFERED_PARTIAL",
      "BODY_SEND_MODE_NONE"],
    var.ext_proc.response_body_mode)
    error_message = "Variable response_body_mode must be of {BODY_SEND_MODE_STREAMED, BODY_SEND_MODE_BUFFERED, BODY_SEND_MODE_BUFFERED_PARTIAL, BODY_SEND_MODE_NONE}"

  }
}

variable "hsl_server" {
  type = object({
    enabled        = bool
    port           = number
    cert_file      = string
    key_file       = string
    max_queue_size = number
    buffer_size    = number
    delimiter      = string
  })

  default = {
    enabled        = false
    port           = 8443
    cert_file      = ""
    key_file       = ""
    max_queue_size = 1000
    buffer_size    = 4096
    delimiter      = "__"
  }
}

variable "apigee_server" {
  type = object({
    enabled           = bool
    message_end_token = string
    server = object({
      port           = number
      cert_file      = string
      key_file       = string
      max_queue_size = number
      buffer_size    = number
    })
  })

  default = {
    enabled           = false
    message_end_token = "__SPAN_END__"
    server = {
      port           = 8444
      cert_file      = ""
      key_file       = ""
      max_queue_size = 1000
      buffer_size    = 4096
    }
  }
}

variable "multiple_services" {
  type = object({
    enabled = bool
    apigee = object({
      service_type = string
      node_port    = number
    })
    hsl = object({
      service_type = string
      node_port    = number
    })
  })

  default = {
    enabled = false
    apigee = {
      service_type = "ClusterIP"
      node_port    = 0
    }
    hsl = {
      service_type = "ClusterIP"
      node_port    = 0
    }
  }
}

variable "pprof_server" {
  type = object({
    enabled  = bool
    endpoint = string
  })

  default = {
    enabled  = true
    endpoint = "127.0.0.1:1777"
  }
}

variable "additional_global_labels" {
  type        = map(string)
  description = "A map of labels added to all traceable resources"
  default     = {}
}

variable "additional_global_annotations" {
  type        = map(string)
  description = "A map of annotations added to all traceable resources"
  default     = {}
}

variable "ext_cap_metrics_config" {
  type = object({
    enabled        = bool
    max_queue_size = number
    endpoint_config = object({
      enabled       = bool
      max_endpoints = number
      logging = object({
        enabled   = bool
        frequency = string
      })
    })
    logging = object({
      enabled   = bool
      frequency = string
    })
    exporter = object({
      enabled            = bool
      export_interval_ms = number
      export_timeout_ms  = number
    })
  })

  default = {
    enabled        = false
    max_queue_size = 9216
    endpoint_config = {
      enabled       = false
      max_endpoints = 5000
      logging = {
        enabled   = false
        frequency = "30m"
      }
    }
    logging = {
      enabled   = false
      frequency = "30m"
    }
    exporter = {
      enabled            = false
      export_interval_ms = 60000
      export_timeout_ms  = 30000
    }
  }
}

variable "service_account_name" {
  type        = string
  description = "traceable-agent service account name"
  default     = "traceable-agent-service-account"
}

variable "ebpf_service_account_name" {
  type        = string
  description = "ebpf tracer service account name"
  default     = "traceable-agent-ebpf-service-account"
}

variable "grpc_to_http" {
  type = object({
    image                     = string
    platform_host             = string
    enabled                   = bool
    platform_port             = number
    port                      = number
    server_cert_secret_name   = string
    server_key_secret_name    = string
    proxy_host                = string
    proxy_port                = number
    proxy_credentials_encoded = string
    resources = object({
      limits   = map(string)
      requests = map(string)
    })
  })

  default = {
    image                     = "envoyproxy/envoy:v1.32.1"
    platform_host             = "api.traceable.ai"
    enabled                   = false
    platform_port             = 443
    port                      = 80
    server_cert_secret_name   = ""
    server_key_secret_name    = ""
    proxy_host                = ""
    proxy_port                = 0
    proxy_credentials_encoded = ""
    resources = {
      limits = {
        cpu    = "500m"
        memory = "512Mi"
      }
      requests = {
        cpu    = "250m"
        memory = "256Mi"
      }
    }
  }
}

variable "priority_class" {
  type = object({
    enabled           = bool
    name              = string
    value             = number
    preemption_policy = string
    global_default    = bool
  })

  default = {
    enabled           = false
    name              = "traceable-agent-priority-class"
    value             = 1000000
    preemption_policy = "Never"
    global_default    = false
  }
}

variable "update_strategy" {
  type = object({
    enabled = bool
    type    = string
    rolling_update = object({
      max_surge       = string
      max_unavailable = string
    })
  })

  default = {
    enabled = false
    type    = "RollingUpdate"
    rolling_update = {
      max_surge       = "0"
      max_unavailable = "1"
    }
  }
}

variable "ebpf_priority_class" {
  type = object({
    enabled           = bool
    name              = string
    value             = number
    preemption_policy = string
    global_default    = bool
  })

  default = {
    enabled           = false
    name              = "traceable-ebpf-tracer-priority-class"
    value             = 1000000
    preemption_policy = "Never"
    global_default    = false
  }
}

variable "ebpf_update_strategy" {
  type = object({
    enabled = bool
    type    = string
    rolling_update = object({
      max_surge       = string
      max_unavailable = string
    })
  })

  default = {
    enabled = false
    type    = "RollingUpdate"
    rolling_update = {
      max_surge       = "0"
      max_unavailable = "1"
    }
  }
}

variable "ebpf_only" {
  type    = bool
  default = false
}

variable "ebpf_reporting_endpoint" {
  type    = string
  default = ""
}

variable "ebpf_remote_endpoint" {
  type    = string
  default = ""
}

variable "ebpf_to_tpa_tls_enabled" {
  type    = bool
  default = false
}

variable "tpa_ca_bundle" {
  type    = string
  default = ""
}

variable "tpa_ca_cert_secret" {
  type = object({
    secret_name       = string
    ca_cert_file_name = string
  })

  default = {
    secret_name       = ""
    ca_cert_file_name = ""
  }
}

variable "tpa_ca_cert_file" {
  type    = string
  default = ""
}

variable "ext_cap_auth" {
  type = object({
    enabled = bool
    }
  )
  default = {
    enabled = false
  }
}

variable "ext_cap_edge_decision_service" {
  type = object({
    enabled              = bool
    endpoint             = string
    timeout_ms           = number
    include_path_regexes = list(string)
    exclude_path_regexes = list(string)
  })
  default = {
    enabled              = false
    endpoint             = "localhost:62060"
    timeout_ms           = 30
    include_path_regexes = []
    exclude_path_regexes = []
  }
}

variable "ext_cap_bot_service" {
  type = object({
    enabled               = bool
    endpoint              = string
    timeout_ms            = number
    include_path_prefixes = list(string)
  })

  default = {
    enabled               = false
    endpoint              = "http://localhost:63050/traceable/captcha/tpa_request"
    timeout_ms            = 30
    include_path_prefixes = ["/traceable/captcha"]
  }
}

variable "use_custom_security_context" {
  type    = bool
  default = false
}

variable "mirroring_security_context" {
  type = object({
    enabled                    = bool
    allow_privilege_escalation = bool
    capabilities = object({
      add  = list(string)
      drop = list(string)
    })
    privileged                = bool
    read_only_root_filesystem = bool
    run_as_group              = string
    run_as_non_root           = bool
    run_as_user               = string
    se_linux_options = object({
      level = string
      role  = string
      type  = string
      user  = string
    })
    seccomp_profile = object({
      localhost_profile = string
      type              = string
    })
  })

  default = {
    enabled                    = false
    allow_privilege_escalation = false
    capabilities = {
      add  = null
      drop = null
    }
    privileged                = false
    read_only_root_filesystem = null
    run_as_group              = null
    run_as_non_root           = null
    run_as_user               = null
    se_linux_options = {
      level = null
      role  = null
      type  = null
      user  = null
    }
    seccomp_profile = {
      localhost_profile = null
      type              = null
    }
  }
}

variable "grpc_to_http_container_security_context" {
  type = object({
    enabled                    = bool
    allow_privilege_escalation = bool
    capabilities = object({
      add  = list(string)
      drop = list(string)
    })
    privileged                = bool
    read_only_root_filesystem = bool
    run_as_group              = string
    run_as_non_root           = bool
    run_as_user               = string
    se_linux_options = object({
      level = string
      role  = string
      type  = string
      user  = string
    })
    seccomp_profile = object({
      localhost_profile = string
      type              = string
    })
  })

  default = {
    enabled                    = false
    allow_privilege_escalation = false
    capabilities = {
      add  = null
      drop = null
    }
    privileged                = false
    read_only_root_filesystem = null
    run_as_group              = null
    run_as_non_root           = null
    run_as_user               = null
    se_linux_options = {
      level = null
      role  = null
      type  = null
      user  = null
    }
    seccomp_profile = {
      localhost_profile = null
      type              = null
    }
  }
}

variable "extension_service_security_context" {
  type = object({
    enabled                    = bool
    allow_privilege_escalation = bool
    capabilities = object({
      add  = list(string)
      drop = list(string)
    })
    privileged                = bool
    read_only_root_filesystem = bool
    run_as_group              = string
    run_as_non_root           = bool
    run_as_user               = string
    se_linux_options = object({
      level = string
      role  = string
      type  = string
      user  = string
    })
    seccomp_profile = object({
      localhost_profile = string
      type              = string
    })
  })

  default = {
    enabled                    = false
    allow_privilege_escalation = false
    capabilities = {
      add  = null
      drop = null
    }
    privileged                = false
    read_only_root_filesystem = null
    run_as_group              = null
    run_as_non_root           = null
    run_as_user               = null
    se_linux_options = {
      level = null
      role  = null
      type  = null
      user  = null
    }
    seccomp_profile = {
      localhost_profile = null
      type              = null
    }
  }
}

variable "ebpf_security_context" {
  type = object({
    enabled                    = bool
    allow_privilege_escalation = bool
    capabilities = object({
      add  = list(string)
      drop = list(string)
    })
    privileged                = bool
    read_only_root_filesystem = bool
    run_as_group              = string
    run_as_non_root           = bool
    run_as_user               = string
    se_linux_options = object({
      level = string
      role  = string
      type  = string
      user  = string
    })
    seccomp_profile = object({
      localhost_profile = string
      type              = string
    })
  })

  default = {
    enabled                    = false
    allow_privilege_escalation = false
    capabilities = {
      add  = null
      drop = null
    }
    privileged                = false
    read_only_root_filesystem = null
    run_as_group              = null
    run_as_non_root           = null
    run_as_user               = null
    se_linux_options = {
      level = null
      role  = null
      type  = null
      user  = null
    }
    seccomp_profile = {
      localhost_profile = null
      type              = null
    }
  }
}

variable "secrets_init_security_context" {
  type = object({
    enabled                    = bool
    allow_privilege_escalation = bool
    capabilities = object({
      add  = list(string)
      drop = list(string)
    })
    privileged                = bool
    read_only_root_filesystem = bool
    run_as_group              = string
    run_as_non_root           = bool
    run_as_user               = string
    se_linux_options = object({
      level = string
      role  = string
      type  = string
      user  = string
    })
    seccomp_profile = object({
      localhost_profile = string
      type              = string
    })
  })

  default = {
    enabled                    = false
    allow_privilege_escalation = false
    capabilities = {
      add  = null
      drop = null
    }
    privileged                = false
    read_only_root_filesystem = null
    run_as_group              = null
    run_as_non_root           = null
    run_as_user               = null
    se_linux_options = {
      level = null
      role  = null
      type  = null
      user  = null
    }
    seccomp_profile = {
      localhost_profile = null
      type              = null
    }
  }
}

variable "common_container_security_context" {
  type = object({
    enabled                    = bool
    allow_privilege_escalation = bool
    capabilities = object({
      add  = list(string)
      drop = list(string)
    })
    privileged                = bool
    read_only_root_filesystem = bool
    run_as_group              = string
    run_as_non_root           = bool
    run_as_user               = string
    se_linux_options = object({
      level = string
      role  = string
      type  = string
      user  = string
    })
    seccomp_profile = object({
      localhost_profile = string
      type              = string
    })
  })

  default = {
    enabled                    = false
    allow_privilege_escalation = false
    capabilities = {
      add  = null
      drop = null
    }
    privileged                = false
    read_only_root_filesystem = null
    run_as_group              = null
    run_as_non_root           = null
    run_as_user               = null
    se_linux_options = {
      level = null
      role  = null
      type  = null
      user  = null
    }
    seccomp_profile = {
      localhost_profile = null
      type              = null
    }
  }
}

variable "batch_processor_create_batch_per_token_enabled" {
  type    = bool
  default = false
}

# This will enable token based authentication at agentmanager, collector and ext_cap.
variable "tracer_auth" {
  type = object({
    enabled = bool
  })

  default = {
    enabled = false
  }
}

variable "ext_cap_evaluate_eds_first" {
  type    = bool
  default = false
}

variable "ext_cap_parser_config" {
  type = object({
    max_body_size = number
    graphql = object({
      enabled = bool
    })
  })

  default = {
    max_body_size = 131072 // 128KB
    graphql = {
      enabled = false
    }
  }
}

variable "tpa_environment_variables" {
  type = list(object({
    name  = string
    value = string
  }))
  default = []
}

variable "ebpf_environment_variables" {
  type = list(object({
    name  = string
    value = string
  }))
  default = []
}

variable "ext_cap_blocking_skip_client_spans" {
  type    = bool
  default = true
}
