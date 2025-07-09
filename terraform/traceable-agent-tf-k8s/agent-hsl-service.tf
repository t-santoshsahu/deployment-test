resource "kubernetes_service" "traceable-agent-hsl" {
  count = var.ebpf_only == false && var.multiple_services.enabled == true && var.hsl_server.enabled == true ? 1 : 0
  metadata {
    name        = "agent-hsl"
    namespace   = var.namespace
    labels      = local.labels
    annotations = var.additional_global_annotations
  }

  spec {
    type = var.multiple_services.hsl.service_type
    port {
      port        = var.hsl_server.port
      name        = "hsl-server"
      protocol    = "TCP"
      target_port = var.hsl_server.port
      node_port   = var.multiple_services.hsl.service_type == "NodePort" && var.multiple_services.hsl.node_port > 0 ? var.multiple_services.hsl.node_port : null
    }

    selector = {
      "app.kubernetes.io/name"     = local.deployment_name
      "app.kubernetes.io/instance" = local.deployment_instance
    }
  }
}
