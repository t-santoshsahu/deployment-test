resource "kubernetes_deployment" "traceable-agent" {
  count      = var.ebpf_only == false && var.run_as_daemon_set == false ? 1 : 0
  depends_on = [kubernetes_config_map.traceable-agent-config-map, kubernetes_service_account.traceable-agent-service-account]
  metadata {
    name        = local.deployment_name
    namespace   = var.namespace
    labels      = local.labels
    annotations = merge(local.deployment_annotations, var.additional_global_annotations)
  }

  spec {
    replicas = var.deployment_replica_count
    dynamic "strategy" {
      for_each = var.update_strategy.enabled == true ? [""] : []
      content {
        type = var.update_strategy.type
        dynamic "rolling_update" {
          for_each = var.update_strategy.type == "RollingUpdate" ? [""] : []
          content {
            max_surge       = var.update_strategy.rolling_update.max_surge
            max_unavailable = var.update_strategy.rolling_update.max_unavailable
          }
        }
      }
    }

    # Note: The deployment spec is very similar to the daemonset spec. The deployment spec adds replica
    # attribute. So any changes made here should be made to the deployment spec as well.
    selector {
      match_labels = {
        "app.kubernetes.io/name"     = local.deployment_name
        "app.kubernetes.io/instance" = local.deployment_instance
      }
    }

    template {
      metadata {
        labels = {
          "app.kubernetes.io/name"      = local.deployment_name
          "app.kubernetes.io/instance"  = local.deployment_instance
          "app.kubernetes.io/component" = "traceable-agent"
        }
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
        service_account_name = "${local.deployment_name}-service-account"
        node_selector        = var.node_selectors
        priority_class_name  = var.priority_class.enabled ? var.priority_class.name : null
        affinity {
          node_affinity {
            required_during_scheduling_ignored_during_execution {
              dynamic "node_selector_term" {
                for_each = var.node_affinity_match_expressions
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
          dynamic "pod_affinity" {
            for_each = length(var.pod_affinity) > 0 ? [1] : []
            content {
              dynamic "required_during_scheduling_ignored_during_execution" {
                for_each = var.pod_affinity
                content {
                  topology_key = required_during_scheduling_ignored_during_execution.value.topology_key
                  dynamic "label_selector" {
                    for_each = required_during_scheduling_ignored_during_execution.value.label_selector
                    content {
                      dynamic "match_expressions" {
                        for_each = label_selector.value.match_expressions
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
          dynamic "pod_anti_affinity" {
            for_each = length(var.pod_anti_affinity) > 0 ? [1] : []
            content {
              dynamic "required_during_scheduling_ignored_during_execution" {
                for_each = var.pod_anti_affinity
                content {
                  topology_key = required_during_scheduling_ignored_during_execution.value.topology_key
                  dynamic "label_selector" {
                    for_each = required_during_scheduling_ignored_during_execution.value.label_selector
                    content {
                      dynamic "match_expressions" {
                        for_each = label_selector.value.match_expressions
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
        }

        dynamic "topology_spread_constraint" {
          for_each = var.topology_spread_constraint
          content {
            dynamic "label_selector" {
              for_each = topology_spread_constraint.value.label_selector
              content {
                dynamic "match_expressions" {
                  for_each = label_selector.value.match_expressions
                  content {
                    key      = match_expressions.value.key
                    operator = match_expressions.value.operator
                    values   = (length(match_expressions.value.values) > 0 ? match_expressions.value.values : null)
                  }
                }
              }
            }
            match_label_keys     = lookup(topology_spread_constraint.value, "match_label_keys", null)
            max_skew             = lookup(topology_spread_constraint.value, "max_skew", null)
            min_domains          = lookup(topology_spread_constraint.value, "min_domains", null)
            node_affinity_policy = lookup(topology_spread_constraint.value, "node_affinity_policy", null)
            node_taints_policy   = lookup(topology_spread_constraint.value, "node_taints_policy", null)
            topology_key         = lookup(topology_spread_constraint.value, "topology_key", null)
            when_unsatisfiable   = lookup(topology_spread_constraint.value, "when_unsatisfiable", null)
          }
        }

        dynamic "security_context" {
          for_each = var.tpa_pod_security_context.enabled ? [var.tpa_pod_security_context] : []
          content {
            fs_group               = security_context.value.fs_group
            fs_group_change_policy = security_context.value.fs_group_change_policy
            run_as_group           = security_context.value.run_as_group
            run_as_non_root        = security_context.value.run_as_non_root
            run_as_user            = security_context.value.run_as_user
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
            supplemental_groups = security_context.value.supplemental_groups
            sysctl {
              name  = security_context.value.sysctl.name
              value = security_context.value.sysctl.value
            }
            windows_options {
              gmsa_credential_spec      = security_context.value.windows_options.gmsa_credential_spec
              gmsa_credential_spec_name = security_context.value.windows_options.gmsa_credential_spec_name
              host_process              = security_context.value.windows_options.host_process
              run_as_username           = security_context.value.windows_options.run_as_username
            }
          }
        }

        dynamic "init_container" {
          for_each = local.bootstrap_refresh_token_from_gcp == true ? [""] : []
          content {
            name  = "secrets-init"
            image = "traceableai/secrets-init:0.4.9"
            args  = ["copy", "/secrets/"]
            volume_mount {
              name       = "secrets-init-volume"
              mount_path = "/secrets/"
            }

            dynamic "security_context" {
              for_each = var.use_custom_security_context && (var.secrets_init_security_context.enabled || var.common_container_security_context.enabled) ? (var.secrets_init_security_context.enabled ? [var.secrets_init_security_context] : [var.common_container_security_context]) : []
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

        container {
          image             = "${local.image_registry_with_suffix}/${var.image_name}${local.tpa_image_separator}${var.image_version}"
          image_pull_policy = var.image_pull_policy
          name              = local.deployment_name

          env {
            name  = "TA_ENVIRONMENT"
            value = var.environment
          }

          env {
            name  = "CLUSTER_NAME"
            value = var.cluster_name
          }

          env {
            name  = "DEPLOYMENT_NAME"
            value = local.deployment_name
          }

          env {
            name = "NODE_NAME"
            value_from {
              field_ref {
                field_path = "spec.nodeName"
              }
            }
          }

          env {
            name = "NAMESPACE_NAME"
            value_from {
              field_ref {
                field_path = "metadata.namespace"
              }
            }
          }

          dynamic "env" {
            for_each = var.injector_enabled == true && local.create_private_registry_secret == true ? [local.image_pull_credentials_json] : []
            content {
              name  = "TA_IMAGE_PULL_SECRET"
              value = base64encode(env.value)
            }
          }

          dynamic "env" {
            for_each = var.injector_enabled == true && var.image_pull_secret_name != "" ? [var.image_pull_secret_name] : []
            content {
              name  = "TA_IMAGE_PULL_SECRET_NAME"
              value = env.value
            }
          }

          dynamic "env" {
            for_each = length(var.refresh_token_file) == 0 && local.bootstrap_refresh_token_from_gcp != true && local.use_external_token_secret != true && var.ext_cap_auth.enabled == false ? [1] : []
            content {
              name = "TA_REFRESH_TOKEN"
              value_from {
                secret_key_ref {
                  name = local.token_secret_name
                  key  = local.token_secret_key
                }
              }
            }
          }

          dynamic "env" {
            for_each = local.bootstrap_refresh_token_from_gcp == true ? [1] : []
            content {
              name  = "TA_REFRESH_TOKEN"
              value = "gcp:secretmanager:projects/${var.refresh_token_gcp_secret_project}/secrets/${var.refresh_token_gcp_secret_name}"
            }
          }

          dynamic "env" {
            for_each = length(var.https_proxy) == 0 ? [] : [var.https_proxy]
            content {
              name  = "https_proxy"
              value = var.https_proxy
            }
          }

          dynamic "env" {
            for_each = length(var.http_proxy) == 0 ? [] : [var.http_proxy]
            content {
              name  = "http_proxy"
              value = var.http_proxy
            }
          }

          dynamic "env" {
            for_each = length(var.no_proxy) == 0 ? [] : [var.no_proxy]
            content {
              name  = "no_proxy"
              value = var.no_proxy
            }
          }

          dynamic "env" {
            for_each = var.tpa_environment_variables
            content {
              name  = env.value.name
              value = env.value.value
            }
          }

          command = local.tpa_command_list
          args    = local.tpa_args_list

          # Names for container ports have some restrictions eg. they cannot be more than 15 characters
          # and they can only contain alphanumeric characters or hyphen (no underscores). So will leave out
          # names for the container ports.
          port {
            container_port = var.server_port
          }

          port {
            container_port = var.rest_server_port
          }

          dynamic "port" {
            for_each = var.injector_enabled == true ? [""] : []
            content {
              container_port = var.tls_server_port
            }
          }

          dynamic "port" {
            for_each = var.collector_enabled == true ? local.collector_ports : []
            content {
              container_port = port.value.container_port
            }
          }

          volume_mount {
            name       = "${local.traceable_agent_config_map}-volume"
            mount_path = "/conf/agent"
          }

          dynamic "volume_mount" {
            for_each = local.add_tls_certs_volume == true ? [""] : []
            content {
              name       = "${local.deployment_name}-cert-volume"
              mount_path = "/conf/certs"
              read_only  = true
            }
          }

          dynamic "volume_mount" {
            for_each = local.add_mtls_certs_volume == true ? [""] : []
            content {
              name       = "${local.mtls_cert_key_secret_name}-remote-client-cert-key-volume"
              mount_path = "/conf/remote/client-certs"
              read_only  = true
            }
          }

          volume_mount {
            name       = "${local.deployment_name}-persistence-volume"
            mount_path = local.persistence_directory
          }

          dynamic "volume_mount" {
            for_each = local.add_remote_tls_ca_cert_volume == true ? [""] : []
            content {
              name       = "${local.deployment_name}-remote-ca-cert-volume"
              mount_path = "/conf/remote/certs"
              read_only  = true
            }
          }

          dynamic "volume_mount" {
            for_each = local.use_external_token_secret == true ? [""] : []
            content {
              name       = "${local.deployment_name}-token-volume"
              mount_path = "/conf/token"
              read_only  = true
            }
          }
          dynamic "volume_mount" {
            for_each = local.pod_mirroring_enabled == true ? [""] : []
            content {
              name       = "${local.deployment_name}-mirror-volume"
              mount_path = var.daemon_set_mirroring.sock_addr_volume_path
            }
          }
          dynamic "volume_mount" {
            for_each = local.bootstrap_refresh_token_from_gcp == true ? [""] : []
            content {
              name       = "secrets-init-volume"
              mount_path = "/secrets/"
            }
          }

          resources {
            limits = {
              cpu    = var.resources.limits.cpu
              memory = var.resources.limits.memory
            }
            requests = {
              cpu    = var.resources.requests.cpu
              memory = var.resources.requests.memory
            }
          }

          readiness_probe {
            tcp_socket {
              port = var.server_port
            }

            initial_delay_seconds = 5
            period_seconds        = 10
          }
          liveness_probe {
            tcp_socket {
              port = var.server_port
            }

            initial_delay_seconds = 5
            period_seconds        = 10
          }

          dynamic "security_context" {
            for_each = var.use_custom_security_context == false && (var.tls_server_port == "443" || var.injector_enabled) ? [""] : []
            content {
              run_as_user = var.security_context.run_as_user == null ? 0 : var.security_context.run_as_user
            }
          }

          dynamic "security_context" {
            for_each = var.use_custom_security_context && (var.security_context.enabled || var.common_container_security_context.enabled) ? (var.security_context.enabled ? [var.security_context] : [var.common_container_security_context]) : []
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
        dynamic "container" {
          for_each = var.extension_service.run_with_deployment == true ? [1] : []
          content {
            name              = var.extension_service.image_name
            image             = "${local.image_registry_with_suffix}/${var.extension_service.image_name}{local.extension_image_separator}${var.extension_service.image_version}"
            image_pull_policy = var.image_pull_policy
            command           = ["python", "app.py"]
            env {
              name  = "PORT"
              value = tostring(var.extension_service.port)
            }
            resources {
              limits = {
                cpu    = var.extension_service.resources.limits.cpu
                memory = var.extension_service.resources.limits.memory
              }
              requests = {
                cpu    = var.extension_service.resources.requests.cpu
                memory = var.extension_service.resources.requests.memory
              }
            }
            port {
              container_port = var.extension_service.port
            }
            dynamic "security_context" {
              for_each = var.use_custom_security_context && (var.extension_service_security_context.enabled || var.common_container_security_context.enabled) ? (var.extension_service_security_context.enabled ? [var.extension_service_security_context] : [var.common_container_security_context]) : []
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

        dynamic "container" {
          for_each = var.grpc_to_http.enabled == true ? [""] : []
          content {
            name  = "traceable-grpc-to-http"
            image = "${var.image_credentials.registry}/${var.grpc_to_http.image}"

            port {
              container_port = var.grpc_to_http.port
            }

            resources {
              limits = {
                cpu    = var.grpc_to_http.resources.limits.cpu
                memory = var.grpc_to_http.resources.limits.memory
              }
              requests = {
                cpu    = var.grpc_to_http.resources.requests.cpu
                memory = var.grpc_to_http.resources.requests.memory
              }
            }

            dynamic "volume_mount" {
              for_each = var.grpc_to_http.enabled == true ? [""] : []
              content {
                name       = "traceable-grpc-to-http-proxy-config-map-volume"
                mount_path = "/etc/envoy/envoy.yaml"
                sub_path   = "envoy.yaml"
                read_only  = true
              }
            }

            dynamic "volume_mount" {
              for_each = var.grpc_to_http.server_cert_secret_name != "" ? [""] : []
              content {
                name       = "server-cert"
                mount_path = "/etc/certs/server.crt"
                sub_path   = "server.crt"
                read_only  = true
              }
            }

            dynamic "volume_mount" {
              for_each = var.grpc_to_http.server_key_secret_name != "" ? [""] : []
              content {
                name       = "server-key"
                mount_path = "/etc/certs/server.key"
                sub_path   = "server.key"
                read_only  = true
              }
            }

            dynamic "security_context" {
              for_each = var.use_custom_security_context && (var.grpc_to_http_container_security_context.enabled || var.common_container_security_context.enabled) ? (var.grpc_to_http_container_security_context.enabled ? [var.grpc_to_http_container_security_context] : [var.common_container_security_context]) : []
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

        dynamic "container" {
          for_each = local.pod_mirroring_enabled == true ? [""] : []
          content {
            image             = "${local.image_registry_with_suffix}/${var.suricata_image_name}${local.suricata_image_separator}${var.suricata_version}"
            image_pull_policy = var.image_pull_policy
            name              = "traceable-mirror"
            command           = ["/bin/sh", "-c", "/usr/bin/suricata -c /etc/suricata/suricata.yaml --pidfile /var/run/suricata.pid --pcap=any ${local.mirroring_bpf_filter} "]
            volume_mount {
              name       = "${local.deployment_name}-mirror-volume"
              mount_path = "/var/log/suricata"
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
                run_as_user = 0
              }
            }
            dynamic "security_context" {
              for_each = var.use_custom_security_context && (var.mirroring_security_context.enabled || var.common_container_security_context.enabled) ? (var.mirroring_security_context.enabled ? [var.mirroring_security_context] : [var.common_container_security_context]) : []
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
            port {
              container_port = 4789
            }
          }
        }
        volume {
          name = "${local.traceable_agent_config_map}-volume"
          config_map {
            name = local.traceable_agent_config_map
          }
        }

        dynamic "volume" {
          for_each = local.add_tls_certs_volume == true ? [""] : []
          content {
            name = "${local.deployment_name}-cert-volume"
            secret {
              secret_name = local.cert_secret_name
            }
          }
        }

        dynamic "volume" {
          for_each = local.add_mtls_certs_volume == true ? [local.mtls_cert_key_secret_name] : []
          content {
            name = "${local.mtls_cert_key_secret_name}-remote-client-cert-key-volume"
            secret {
              secret_name = local.mtls_cert_key_secret_name
            }
          }
        }

        dynamic "volume" {
          for_each = var.persistence_pvc_name != "" ? [""] : []
          content {
            name = "${local.deployment_name}-persistence-volume"
            persistent_volume_claim {
              claim_name = var.persistence_pvc_name
            }
          }
        }
        dynamic "volume" {
          for_each = var.persistence_pvc_name == "" ? [""] : []
          content {
            name = "${local.deployment_name}-persistence-volume"
            empty_dir {
            }
          }
        }
        dynamic "volume" {
          for_each = local.add_remote_tls_ca_cert_volume == true ? [""] : []
          content {
            name = "${local.deployment_name}-remote-ca-cert-volume"
            secret {
              secret_name = local.remote_tls_ca_cert_secret_name
            }
          }
        }
        dynamic "volume" {
          for_each = local.use_external_token_secret == true ? [""] : []
          content {
            name = "${local.deployment_name}-token-volume"
            secret {
              secret_name = local.token_secret_name
              items {
                key  = local.token_secret_key
                path = "refresh-token"
              }
            }
          }
        }
        dynamic "volume" {
          for_each = local.pod_mirroring_enabled == true ? [""] : []
          content {
            name = "${local.deployment_name}-mirror-volume"
            empty_dir {
            }
          }
        }
        dynamic "volume" {
          for_each = local.bootstrap_refresh_token_from_gcp == true ? [""] : []
          content {
            name = "secrets-init-volume"
            empty_dir {
            }
          }
        }

        dynamic "volume" {
          for_each = var.grpc_to_http.enabled == true ? [""] : []
          content {
            name = "traceable-grpc-to-http-proxy-config-map-volume"
            config_map {
              name = "traceable-grpc-to-http-proxy-configmap"
            }
          }
        }

        dynamic "volume" {
          for_each = var.grpc_to_http.server_cert_secret_name != "" ? [""] : []
          content {
            name = "server-cert"
            secret {
              secret_name = var.grpc_to_http.server_cert_secret_name
            }
          }
        }

        dynamic "volume" {
          for_each = var.grpc_to_http.server_key_secret_name != "" ? [""] : []
          content {
            name = "server-key"
            secret {
              secret_name = var.grpc_to_http.server_key_secret_name
            }
          }
        }

        dynamic "toleration" {
          for_each = var.tolerations
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
