resource "kubernetes_horizontal_pod_autoscaler_v2" "traceable-agent" {
  count = var.ebpf_only == false && var.autoscaling.enabled == true && var.run_as_daemon_set == false ? 1 : 0
  metadata {
    name        = local.deployment_name
    namespace   = var.namespace
    labels      = local.labels
    annotations = var.additional_global_annotations
  }

  spec {
    min_replicas = var.autoscaling.min_replicas
    max_replicas = var.autoscaling.max_replicas

    scale_target_ref {
      api_version = "apps/v1"
      kind        = "Deployment"
      name        = local.deployment_name
    }

    metric {
      type = "Resource"
      resource {
        name = "memory"
        target {
          type                = "Utilization"
          average_utilization = var.autoscaling.target_memory_utilization
        }
      }
    }
    metric {
      type = "Resource"
      resource {
        name = "cpu"
        target {
          type                = "Utilization"
          average_utilization = var.autoscaling.target_cpu_utilization
        }
      }
    }
  }
}
