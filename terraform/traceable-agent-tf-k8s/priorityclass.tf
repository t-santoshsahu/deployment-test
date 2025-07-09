resource "kubernetes_priority_class" "traceable-agent-priority-class" {
  count = var.ebpf_only == false && var.priority_class.enabled ? 1 : 0
  metadata {
    name        = var.priority_class.name
    labels      = local.labels
    annotations = var.additional_global_annotations
  }

  value             = var.priority_class.value
  preemption_policy = var.priority_class.preemption_policy
  global_default    = var.priority_class.global_default
  description       = "traceable-agent pod priority class"
}
