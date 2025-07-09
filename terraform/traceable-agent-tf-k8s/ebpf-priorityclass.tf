resource "kubernetes_priority_class" "traceable-ebpf-tracer-priority-class" {
  count = var.ebpf_capture_enabled && var.ebpf_priority_class.enabled ? 1 : 0
  metadata {
    name        = var.ebpf_priority_class.name
    labels      = local.labels
    annotations = var.additional_global_annotations
  }

  value             = var.ebpf_priority_class.value
  preemption_policy = var.ebpf_priority_class.preemption_policy
  global_default    = var.ebpf_priority_class.global_default
  description       = "EBPF tracer pod priority class."
}