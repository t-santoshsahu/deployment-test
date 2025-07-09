resource "kubernetes_cluster_role" "traceable-agent-cluster-role" {
  count = var.ebpf_only == false && var.cluster_roles_enabled ? 1 : 0
  metadata {
    name        = "${local.deployment_name}-cluster-role-${var.namespace}"
    labels      = local.labels
    annotations = var.additional_global_annotations
  }

  dynamic "rule" {
    for_each = var.injector_enabled == true ? local.injector_rules : []
    content {
      api_groups = rule.value.api_groups
      resources  = rule.value.resources
      verbs      = rule.value.verbs
    }
  }

  dynamic "rule" {
    for_each = var.k8sprocessor_enabled == true ? local.cluster_role_k8sprocessor_rules : []
    content {
      api_groups = rule.value.api_groups
      resources  = rule.value.resources
      verbs      = rule.value.verbs
    }
  }

  dynamic "rule" {
    for_each = (local.mirroring_enabled == true) ? local.cluster_role_daemon_set_mirroring_rules : []
    content {
      api_groups = rule.value.api_groups
      resources  = rule.value.resources
      verbs      = rule.value.verbs
    }
  }

  dynamic "rule" {
    for_each = var.pod_security_policies_enabled == true ? local.cluster_role_pod_security_policy_rules : []
    content {
      api_groups     = rule.value.api_groups
      resources      = rule.value.resources
      verbs          = rule.value.verbs
      resource_names = rule.value.resource_names
    }
  }
}

locals {
  cluster_role_pod_security_policy_rules = [
    {
      api_groups     = ["policy"]
      resources      = ["podsecuritypolicies"]
      verbs          = ["use"]
      resource_names = ["${local.deployment_name}-pod-security-policy"]
    }
  ]

  cluster_role_k8sprocessor_rules = [
    {
      api_groups = ["", "apps"]
      resources  = ["deployments", "nodes", "pods"]
      verbs      = ["get", "watch", "list"]
    }
  ]

  injector_rules_1 = var.injector_enabled == true && (local.create_private_registry_secret == true || var.image_pull_secret_name != "") ? [
    {
      api_groups = [""]
      resources  = ["secrets"]
      verbs      = ["get", "create"]
    }
  ] : []

  injector_rules = concat(local.injector_rules_1, [
    {
      api_groups = [""]
      resources  = ["namespaces"]
      verbs      = ["get"]
    },
    {
      api_groups = [""]
      resources  = ["configmaps"]
      verbs      = ["get", "update"]
    },
  ])
}
