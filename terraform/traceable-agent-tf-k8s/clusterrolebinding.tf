resource "kubernetes_cluster_role_binding" "traceable-agent-cluster-role-binding" {
  count = var.ebpf_only == false && var.cluster_roles_enabled ? 1 : 0
  metadata {
    name        = "${local.deployment_name}-cluster-role-binding-${var.namespace}"
    labels      = local.labels
    annotations = var.additional_global_annotations
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = "${local.deployment_name}-cluster-role-${var.namespace}"
  }
  subject {
    kind      = "ServiceAccount"
    name      = var.service_account_name
    namespace = var.namespace
  }
}
