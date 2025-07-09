resource "kubernetes_service" "traceable-agent-injector" {
  count = var.ebpf_only == false && var.injector_enabled == true && var.service_type == "Headless" ? 1 : 0
  metadata {
    name        = local.injector_service_host_name
    namespace   = var.namespace
    labels      = local.labels
    annotations = var.additional_global_annotations
  }

  spec {
    type = "ClusterIP"
    dynamic "port" {
      for_each = local.add_tls_certs == true ? [""] : []
      content {
        port        = var.tls_server_port
        name        = "https-agent"
        protocol    = "TCP"
        target_port = var.tls_server_port
      }
    }

    selector = {
      "app.kubernetes.io/name"     = local.deployment_name
      "app.kubernetes.io/instance" = local.deployment_instance
    }
  }
}
