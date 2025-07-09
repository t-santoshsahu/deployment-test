resource "kubernetes_pod_security_policy" "traceable-agent-ebpf-pod-security-policy" {
  count = var.pod_security_policies_enabled ? 1 : 0
  metadata {
    name        = "${local.deployment_name}-ebpf-pod-security-policy"
    labels      = local.labels
    annotations = var.additional_global_annotations
  }

  spec {
    privileged           = true
    allowed_capabilities = local.ebpf_allowed_capabilities

    se_linux {
      rule = "RunAsAny"
    }

    supplemental_groups {
      rule = "RunAsAny"
    }

    run_as_user {
      rule = "RunAsAny"
    }

    fs_group {
      rule = "RunAsAny"
    }

    volumes = ["*"]
  }
}
