resource "kubernetes_daemonset" "ebpf" {
  count      = var.ebpf_capture_enabled == true ? 1 : 0
  depends_on = [kubernetes_config_map.traceable-agent-config-map, kubernetes_service_account.traceable-agent-ebpf-service-account]
  metadata {
    name        = "traceable-ebpf-tracer-ds"
    namespace   = var.namespace
    labels      = local.labels
    annotations = merge(local.deployment_annotations, var.additional_global_annotations)
  }

  spec {
    dynamic "strategy" {
      for_each = var.ebpf_update_strategy.enabled == true ? [""] : []
      content {
        type = var.ebpf_update_strategy.type
        dynamic "rolling_update" {
          for_each = var.ebpf_update_strategy.type == "RollingUpdate" ? [""] : []
          content {
            # For terraform k8s max_surge is not available as a config property in daemonset update strategy
            max_unavailable = var.ebpf_update_strategy.rolling_update.max_unavailable
          }
        }
      }
    }
    selector {
      match_labels = {
        "app.kubernetes.io/name"     = "${local.deployment_name}-ebpf"
        "app.kubernetes.io/instance" = "${local.deployment_instance}-ebpf"
      }
    }

    template {
      metadata {
        labels = merge({
          "app.kubernetes.io/name"      = "${local.deployment_name}-ebpf"
          "app.kubernetes.io/instance"  = "${local.deployment_instance}-ebpf"
          "app.kubernetes.io/component" = "traceable-agent"
        }, var.additional_global_labels)
        annotations = merge(local.deployment_annotations, var.additional_global_annotations)
      }

      spec {
        dynamic "image_pull_secrets" {
          iterator = secret
          for_each = { for v in local.image_pull_secrets : v => v }
          content {
            name = secret.value
          }
        }
        node_selector = var.ebpf_node_selectors
        dynamic "affinity" {
          for_each = var.ebpf_capture_enabled == true ? [""] : []
          content {
            node_affinity {
              required_during_scheduling_ignored_during_execution {
                dynamic "node_selector_term" {
                  for_each = var.ebpf_node_affinity_match_expressions
                  content {
                    match_expressions {
                      key      = "kubernetes.io/os"
                      operator = "Exists"
                    }
                    match_expressions {
                      key      = "kubernetes.io/os"
                      operator = "In"
                      values   = ["linux"]
                    }
                    dynamic "match_expressions" {
                      for_each = var.ebpf_deploy_on_master == false ? [""] : []
                      content {
                        key      = "node-role.kubernetes.io/control-plane"
                        operator = "DoesNotExist"
                      }
                    }
                    dynamic "match_expressions" {
                      for_each = node_selector_term.value.match_expressions
                      content {
                        key      = match_expressions.value.key
                        operator = match_expressions.value.operator
                        values   = (length(match_expressions.value.values) > 0 ? match_expressions.value.values : null)
                      }
                    }
                  }
                }
              }
            }
          }
        }
        service_account_name = "${local.deployment_name}-ebpf-service-account"
        host_pid             = var.ebpf_enable_java_tls_capture || length(var.ebpf_ssl_keylog_include_rules) > 0
        priority_class_name  = var.ebpf_capture_enabled && var.ebpf_priority_class.enabled ? var.ebpf_priority_class.name : null
        dynamic "container" {
          for_each = var.ebpf_capture_enabled == true ? [""] : []
          content {
            image             = "${local.image_registry_with_suffix}/${var.ebpf_tracer_image_name}${local.ebpf_image_separator}${var.ebpf_tracer_version}"
            image_pull_policy = var.image_pull_policy
            name              = "traceable-ebpf-tracer"
            args              = ["-f", "/conf/ebpfconfig.yaml"]
            env {
              name = "NODE_NAME"
              value_from {
                field_ref {
                  field_path = "spec.nodeName"
                }
              }
            }
            env {
              name = "NODE_IP"
              value_from {
                field_ref {
                  field_path = "status.hostIP"
                }
              }
            }

            dynamic "env" {
              for_each = var.ebpf_environment_variables
              content {
                name  = env.value.name
                value = env.value.value
              }
            }

            dynamic "volume_mount" {
              for_each = var.ebpf_enable_java_tls_capture == false && length(var.ebpf_ssl_keylog_include_rules) == 0 ? [""] : []
              content {
                name       = "${local.deployment_name}-proc-volume"
                mount_path = "/hostproc"
                read_only  = true
              }
            }

            volume_mount {
              name       = "${local.deployment_name}-sys-volume"
              mount_path = "/sys"
            }

            volume_mount {
              name       = "${local.traceable_ebpf_config_map}-volume"
              mount_path = "/conf"
            }

            dynamic "volume_mount" {
              for_each = local.add_tpa_tls_ca_cert_for_clients_volume == true ? [""] : []
              content {
                name       = "${local.deployment_name}-cert-volume"
                mount_path = "/conf/certs"
                read_only  = true
              }
            }

            dynamic "volume_mount" {
              for_each = var.ebpf_btf_downloads_path != "" ? [""] : []
              content {
                name       = "ebpf-btf-volume"
                mount_path = var.ebpf_btf_downloads_path
              }
            }

            resources {
              limits = {
                cpu    = var.daemon_set_mirroring.resources.limits.cpu
                memory = var.daemon_set_mirroring.resources.limits.memory
              }
              requests = {
                cpu    = var.daemon_set_mirroring.resources.requests.cpu
                memory = var.daemon_set_mirroring.resources.requests.memory
              }
            }
            dynamic "security_context" {
              for_each = var.use_custom_security_context == false ? [""] : []
              content {
                run_as_user                = 0
                privileged                 = var.ebpf_run_as_privileged
                allow_privilege_escalation = var.ebpf_run_as_privileged
                read_only_root_filesystem  = true
                capabilities {
                  add = var.ebpf_allowed_capabilities
                }
                dynamic "se_linux_options" {
                  for_each = var.ebpf_se_linux_options_enabled == true ? [""] : []
                  content {
                    role = var.ebpf_se_linux_options_role
                    type = var.ebpf_se_linux_options_type
                    user = var.ebpf_se_linux_options_user
                  }
                }
              }
            }

            dynamic "security_context" {
              for_each = var.use_custom_security_context && (var.ebpf_security_context.enabled || var.common_container_security_context.enabled) ? (var.ebpf_security_context.enabled ? [var.ebpf_security_context] : [var.common_container_security_context]) : []
              content {
                allow_privilege_escalation = security_context.value.allow_privilege_escalation
                capabilities {
                  add  = security_context.value.capabilities.add
                  drop = security_context.value.capabilities.drop
                }
                privileged                = security_context.value.privileged
                read_only_root_filesystem = security_context.value.read_only_root_filesystem
                run_as_group              = security_context.value.run_as_group
                run_as_non_root           = security_context.value.run_as_non_root
                run_as_user               = security_context.value.run_as_user
                se_linux_options {
                  level = security_context.value.se_linux_options.level
                  role  = security_context.value.se_linux_options.role
                  type  = security_context.value.se_linux_options.type
                  user  = security_context.value.se_linux_options.user
                }
                seccomp_profile {
                  localhost_profile = security_context.value.seccomp_profile.localhost_profile
                  type              = security_context.value.seccomp_profile.type
                }
              }
            }
          }
        }

        dynamic "volume" {
          for_each = local.add_tpa_tls_ca_cert_for_clients_volume == true ? [""] : []
          content {
            name = "${local.deployment_name}-cert-volume"
            secret {
              secret_name = local.tpa_tls_ca_cert_for_clients_secret_name
            }
          }
        }

        dynamic "volume" {
          for_each = var.ebpf_enable_java_tls_capture == false && length(var.ebpf_ssl_keylog_include_rules) == 0 ? [""] : []
          content {
            name = "${local.deployment_name}-proc-volume"
            host_path {
              path = "/proc"
            }
          }
        }

        volume {
          name = "${local.deployment_name}-sys-volume"
          host_path {
            path = "/sys"
          }
        }

        volume {
          name = "${local.traceable_ebpf_config_map}-volume"
          config_map {
            name = local.traceable_ebpf_config_map
          }
        }

        dynamic "volume" {
          for_each = var.ebpf_btf_downloads_path != "" ? [""] : []
          content {
            name = "ebpf-btf-volume"
            empty_dir {
              size_limit = "64Mi"
            }
          }
        }

        dynamic "toleration" {
          for_each = var.ebpf_tolerations
          content {
            effect             = toleration.value.effect
            key                = toleration.value.key
            operator           = toleration.value.operator
            toleration_seconds = toleration.value.toleration_seconds
            value              = toleration.value.value
          }
        }
      }
    }
  }
}
