resource "kubernetes_service" "traceable-agent-apigee" {
  count = var.ebpf_only == false && var.multiple_services.enabled == true && var.apigee_server.enabled == true ? 1 : 0
  metadata {
    name        = "agent-apigee"
    namespace   = var.namespace
    labels      = local.labels
    annotations = var.additional_global_annotations
  }

  spec {
    type = var.multiple_services.apigee.service_type
    port {
      port        = var.apigee_server.server.port
      name        = "apigee-server"
      protocol    = "TCP"
      target_port = var.apigee_server.server.port
      node_port   = var.multiple_services.apigee.service_type == "NodePort" && var.multiple_services.apigee.node_port > 0 ? var.multiple_services.apigee.node_port : null
    }

    selector = {
      "app.kubernetes.io/name"     = local.deployment_name
      "app.kubernetes.io/instance" = local.deployment_instance
    }
  }
}
