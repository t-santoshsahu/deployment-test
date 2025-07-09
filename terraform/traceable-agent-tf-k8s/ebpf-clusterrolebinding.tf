resource "kubernetes_cluster_role_binding" "traceable-agent-ebpf-cluster-role-binding" {
  count = var.cluster_roles_enabled && var.ebpf_capture_enabled ? 1 : 0
  metadata {
    name        = "${local.deployment_name}-ebpf-cluster-role-binding-${var.namespace}"
    labels      = local.labels
    annotations = var.additional_global_annotations
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = "${local.deployment_name}-ebpf-cluster-role-${var.namespace}"
  }
  subject {
    kind      = "ServiceAccount"
    name      = var.ebpf_service_account_name
    namespace = var.namespace
  }
}
