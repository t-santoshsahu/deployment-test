resource "kubernetes_pod_disruption_budget" "traceable-agent" {
  count = var.ebpf_only == false && var.run_as_daemon_set == false && (var.pdb_min_available != null || var.pdb_max_unavailable != null) ? 1 : 0
  metadata {
    name        = "traceable-agent"
    namespace   = var.namespace
    labels      = local.labels
    annotations = var.additional_global_annotations
  }
  spec {
    min_available   = var.pdb_min_available
    max_unavailable = var.pdb_max_unavailable
    selector {
      match_labels = {
        "app.kubernetes.io/name"     = local.deployment_name
        "app.kubernetes.io/instance" = local.deployment_instance
      }
    }
  }
}
