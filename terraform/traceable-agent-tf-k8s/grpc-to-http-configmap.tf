resource "kubernetes_config_map" "traceable-grpc-to-http-proxy-configmap" {
  metadata {
    name        = "traceable-grpc-to-http-proxy-configmap"
    namespace   = var.namespace
    labels      = local.labels
    annotations = var.additional_annotations
  }

  data = {
    "envoy.yaml" = <<YAML
static_resources:
  listeners:
    - name: main_listener
      address:
        socket_address:
          address: 0.0.0.0
          port_value: ${var.grpc_to_http.port}
      filter_chains:
        filters:
          - name: envoy.filters.network.http_connection_manager
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
              codec_type: auto
              stat_prefix: ingress_http
              access_log:
                - name: envoy.access_loggers.file
                  typed_config:
                    "@type": type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog
                    path: "/dev/stdout"
              route_config:
                name: local_route
                virtual_hosts:
                  - name: app
                    domains:
                      - "*"
                    routes:
                      - match:
                          prefix: "/"
                        route:
                          host_rewrite_literal:  ${var.grpc_to_http.platform_host}
                          cluster: ${var.grpc_to_http.proxy_host != "" ? "loopback_cluster" : "platform_cluster"}
              http_filters:
                - name: envoy.filters.http.grpc_http1_reverse_bridge
                  typed_config:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.grpc_http1_reverse_bridge.v3.FilterConfig
                    content_type: "application/grpc"
                    withhold_grpc_frames: false

                - name: envoy.filters.http.router
                  typed_config:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
        ${indent(8, local.grpc_to_http_tls_config)}
${var.grpc_to_http.proxy_host != "" ? <<API_PROXY
    - name: api_proxy_listener
      address:
        pipe:
          path: "@/cluster_0"
      filter_chains:
        - filters:
          - name: tcp
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
              stat_prefix: tcp_stats
              cluster: "proxy_cluster"
              tunneling_config:
                hostname: ${var.grpc_to_http.platform_host}:${var.grpc_to_http.platform_port}
                ${indent(16, local.grpc_to_http_auth_config)}
API_PROXY
    : ""}
  clusters:
${var.grpc_to_http.proxy_host != "" ? <<PROXY_CLUSTER
    - name: proxy_cluster
      connect_timeout: 0.25s
      type: strict_dns
      lb_policy: round_robin
      load_assignment:
        cluster_name: proxy_cluster
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address:
                      address: ${var.grpc_to_http.proxy_host}
                      port_value: ${var.grpc_to_http.proxy_port}
    - name: loopback_cluster
      connect_timeout: 5s
      upstream_connection_options:
        tcp_keepalive: {}
      type: STATIC
      load_assignment:
        cluster_name: loopback_cluster
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    pipe:
                      path: "@/cluster_0"
      transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
          sni: ${var.grpc_to_http.platform_host}
PROXY_CLUSTER
  : ""}
    - name: platform_cluster
      connect_timeout: 5s
      type: strict_dns
      lb_policy: round_robin
      load_assignment:
        cluster_name: platform_cluster
        endpoints:
          - lb_endpoints:
            - endpoint:
                address:
                  socket_address:
                    address: ${var.grpc_to_http.platform_host}
                    port_value: ${var.grpc_to_http.platform_port}
      transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
          sni: ${var.grpc_to_http.platform_host}
YAML
}

count = var.grpc_to_http.enabled ? 1 : 0
}
