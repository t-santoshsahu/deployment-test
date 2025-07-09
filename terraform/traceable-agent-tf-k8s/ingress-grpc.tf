resource "kubernetes_ingress" "traceable-agent-grpc" {
  count = var.ebpf_only == false && var.ingress.enabled == true ? 1 : 0
  metadata {
    name        = "${local.deployment_name}-grpc"
    namespace   = var.namespace
    labels      = local.labels
    annotations = merge(var.ingress.grpc.annotations, var.additional_global_annotations)
  }
  spec {
    ingress_class_name = length(var.ingress.ingress_class_name) > 0 ? var.ingress.ingress_class_name : null
    rule {
      host = "opentelemetry.${var.ingress.domain}"
      http {
        path {
          backend {
            service_name = "agent"
            service_port = var.collector.ports.opentelemetry
          }
          path = "/"
        }
      }
    }

    rule {
      host = "agent.${var.ingress.domain}"
      http {
        path {
          backend {
            service_name = "agent"
            service_port = var.server_port
          }
          path = "/"
        }
      }
    }
  }
}
