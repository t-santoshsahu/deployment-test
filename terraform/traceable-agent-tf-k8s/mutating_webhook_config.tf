resource "kubernetes_mutating_webhook_configuration_v1" "injector_mutating_webhook_config" {
  # Create this just when ebpf only mode is false and injector is enabled.
  count = var.ebpf_only == false && var.injector_enabled == true ? 1 : 0
  metadata {
    name        = "${local.deployment_name}-injector-${var.namespace}"
    labels      = local.labels
    annotations = var.additional_global_annotations
  }

  dynamic "webhook" {
    for_each = local.injector_webhooks
    content {
      name                      = webhook.value.name
      admission_review_versions = ["v1", "v1beta1"]
      side_effects              = "None"
      client_config {
        dynamic "service" {
          for_each = var.injector_webhook_domain == "" ? [""] : []
          content {
            name      = local.injector_service_host_name
            namespace = var.namespace
            path      = "/injector/v1/inject-${webhook.value.root_name}"
            port      = var.tls_server_port
          }
        }
        url       = var.injector_webhook_domain != "" ? "https://${var.injector_webhook_domain}/injector/v1/inject-${webhook.value.root_name}" : null
        ca_bundle = local.ca_bundle != "" ? local.ca_bundle : null
      }
      rule {
        api_groups   = [""]
        api_versions = ["v1"]
        operations   = ["CREATE"]
        resources    = ["pods"]
      }
      failure_policy = var.injector.failure_policy
      namespace_selector {
        match_labels = webhook.value.match_labels
      }
    }
  }
}

locals {
  injector_webhooks = [
    {
      name         = "java-injector.${var.namespace}.svc"
      root_name    = "java"
      match_labels = local.java_webhook_match_labels
    },
    {
      name         = "tme-injector.${var.namespace}.svc"
      root_name    = "tme"
      match_labels = local.tme_webhook_match_labels
    },
    {
      name         = "mirror-injector.traceableai.svc"
      root_name    = "mirror"
      match_labels = local.mirror_webhook_match_labels
    },
    {
      name         = "extension-injector.traceableai.svc"
      root_name    = "extension"
      match_labels = local.extension_webhook_match_labels
    },
    {
      name         = "nginx-cpp-injector.traceableai.svc"
      root_name    = "nginx-cpp"
      match_labels = local.nginx_cpp_match_labels
    },
    # Backwards compatibility webhooks. Using the old/deprecated namespaceSelector matchLabels.
    {
      name         = "java-injector-deprecated.${var.namespace}.svc"
      root_name    = "java"
      match_labels = local.java_deprecated_webhook_match_labels
    },
    {
      name         = "tme-injector-deprecated.${var.namespace}.svc"
      root_name    = "tme"
      match_labels = local.tme_deprecated_webhook_match_labels
    }
  ]
}
