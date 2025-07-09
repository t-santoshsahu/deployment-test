resource "kubernetes_cluster_role" "traceable-agent-ebpf-cluster-role" {
  count = var.cluster_roles_enabled && var.ebpf_capture_enabled == true ? 1 : 0
  metadata {
    name        = "${local.deployment_name}-ebpf-cluster-role-${var.namespace}"
    labels      = local.labels
    annotations = var.additional_global_annotations
  }

  dynamic "rule" {
    for_each = local.cluster_role_daemon_set_mirroring_rules
    content {
      api_groups = rule.value.api_groups
      resources  = rule.value.resources
      verbs      = rule.value.verbs
    }
  }

  dynamic "rule" {
    for_each = var.pod_security_policies_enabled == true ? local.ebpf_cluster_role_pod_security_policy_rules : []
    content {
      api_groups     = rule.value.api_groups
      resources      = rule.value.resources
      verbs          = rule.value.verbs
      resource_names = rule.value.resource_names
    }
  }
}

locals {
  ebpf_cluster_role_pod_security_policy_rules = [
    {
      api_groups     = ["policy"]
      resources      = ["podsecuritypolicies"]
      verbs          = ["use"]
      resource_names = ["${local.deployment_name}-ebpf-pod-security-policy"]
    }
  ]
}
