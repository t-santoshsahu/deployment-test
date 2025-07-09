resource "kubernetes_ingress" "traceable-agent" {
  count = var.ebpf_only == false && var.ingress.enabled == true ? 1 : 0
  metadata {
    name        = local.deployment_name
    namespace   = var.namespace
    labels      = local.labels
    annotations = merge(var.ingress.http.annotations, var.additional_global_annotations)
  }
  spec {
    ingress_class_name = length(var.ingress.ingress_class_name) > 0 ? var.ingress.ingress_class_name : null
    rule {
      host = "zipkin.${var.ingress.domain}"
      http {
        path {
          backend {
            service_name = "agent"
            service_port = var.collector.ports.zipkin
          }
          path = "/"
        }
      }
    }
    rule {
      host = "agent-rest.${var.ingress.domain}"
      http {
        path {
          backend {
            service_name = "agent"
            service_port = var.rest_server_port
          }
          path = "/"
        }
      }
    }
  }
}
