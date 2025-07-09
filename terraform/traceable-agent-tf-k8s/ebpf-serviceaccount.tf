resource "kubernetes_service_account" "traceable-agent-ebpf-service-account" {
  count = var.ebpf_capture_enabled == true ? 1 : 0
  metadata {
    name        = var.ebpf_service_account_name
    namespace   = var.namespace
    labels      = local.labels
    annotations = merge(local.service_account_annotations, var.additional_global_annotations)
  }
}
