resource "kubernetes_service" "traceable-agent" {
  count = var.ebpf_only == false ? 1 : 0
  metadata {
    name        = "agent"
    namespace   = var.namespace
    labels      = local.service_labels
    annotations = local.service_annotations
  }

  spec {
    type                    = var.service_type == "Headless" ? "ClusterIP" : var.service_type
    cluster_ip              = var.service_type == "Headless" ? "None" : null
    external_traffic_policy = var.service_external_traffic_policy == "" ? null : var.service_external_traffic_policy
    load_balancer_ip        = var.service_type == "LoadBalancer" && var.load_balancer_ip != "" ? var.load_balancer_ip : null

    dynamic "port" {
      for_each = var.tls_enabled == false && local.single_service_mode == false ? [""] : []
      content {
        port        = var.server_port
        name        = "grpc-agent"
        protocol    = "TCP"
        target_port = var.server_port
      }
    }

    dynamic "port" {
      for_each = var.tls_enabled == false && var.load_balancer_https_agent_service.enabled == false ? [""] : []
      content {
        port        = var.rest_server_port
        name        = var.http_reverse_proxy_enabled ? "grpc-http-agent" : "http-agent"
        protocol    = "TCP"
        target_port = var.rest_server_port
        node_port   = var.service_type == "NodePort" && var.rest_server_node_port != 0 ? var.rest_server_node_port : null
      }
    }

    dynamic "port" {
      for_each = local.add_tls_certs == true && var.load_balancer_https_agent_service.enabled == false ? [""] : []
      content {
        port        = var.tls_server_port
        name        = "https-agent"
        protocol    = "TCP"
        target_port = var.tls_server_port
        node_port   = var.service_type == "NodePort" && var.tls_server_node_port != 0 ? var.tls_server_node_port : null
      }
    }

    dynamic "port" {
      for_each = local.single_service_mode == true && var.service_type == "LoadBalancer" && var.load_balancer_https_agent_service.enabled == true && var.injector_enabled == false ? [""] : []
      content {
        port        = var.load_balancer_https_agent_service.port
        name        = "https-agent"
        protocol    = "TCP"
        target_port = var.load_balancer_https_agent_service.target_port
      }
    }

    dynamic "port" {
      for_each = !var.multiple_services.enabled && var.hsl_server.enabled ? [var.hsl_server] : []
      content {
        port        = port.value.port
        name        = "tcp-hsl"
        protocol    = "TCP"
        target_port = port.value.port
      }
    }

    dynamic "port" {
      for_each = !var.multiple_services.enabled && var.apigee_server.enabled ? [var.apigee_server] : []
      content {
        port        = port.value.server.port
        name        = "tcp-apigee"
        protocol    = "TCP"
        target_port = port.value.server.port
      }
    }

    dynamic "port" {
      for_each = var.tls_enabled == false && var.collector_enabled == true && local.single_service_mode == false ? local.collector_ports : []
      content {
        port        = port.value.service_port
        name        = port.value.name
        protocol    = "TCP"
        target_port = port.value.container_port
      }
    }

    dynamic "port" {
      for_each = var.extension_service.run_with_deployment ? [""] : []
      content {
        port        = var.extension_service.port
        name        = "grpc-extensionservice"
        protocol    = "TCP"
        target_port = var.extension_service.port
      }
    }

    dynamic "port" {
      for_each = local.pod_mirroring_enabled == true ? [""] : []
      content {
        port        = 4789
        name        = "vxlan"
        protocol    = "UDP"
        target_port = 4789
      }
    }
    selector = {
      "app.kubernetes.io/name"     = local.deployment_name
      "app.kubernetes.io/instance" = local.deployment_instance
    }
  }
}
