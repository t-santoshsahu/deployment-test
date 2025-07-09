resource "kubernetes_service_account" "traceable-agent-service-account" {
  count = var.ebpf_only == false ? 1 : 0
  metadata {
    name        = var.service_account_name
    namespace   = var.namespace
    labels      = local.labels
    annotations = merge(local.service_account_annotations, var.additional_global_annotations)
  }
}
