resource "kubernetes_secret" "cluster-regcred" {
  count = local.create_private_registry_secret == true ? 1 : 0
  metadata {
    name        = local.private_registry_regcred
    namespace   = var.namespace
    labels      = local.labels
    annotations = var.additional_global_annotations
  }
  type = "kubernetes.io/dockerconfigjson"
  data = {
    ".dockerconfigjson" = local.image_pull_credentials_json
  }
}

resource "kubernetes_secret" "token" {
  count = var.ebpf_only == false && local.use_external_token_secret == false && var.ext_cap_auth.enabled == false ? (length(var.refresh_token_file) == 0 ? 1 : 0) : 0
  metadata {
    name        = local.token_secret_name
    namespace   = var.namespace
    labels      = local.labels
    annotations = var.additional_global_annotations
  }
  type = "Opaque"
  data = {
    token = var.token
  }
}

resource "kubernetes_secret" "cert" {
  count = var.ebpf_only == false && local.add_tls_certs == true && local.tls_certs_self_gen == true ? 1 : 0
  metadata {
    name        = local.cert_secret_name
    namespace   = var.namespace
    labels      = local.labels
    annotations = var.additional_global_annotations
  }
  type = "Opaque"
  data = {
    "tls.key"     = local.tls_key
    "tls.crt"     = local.tls_crt
    "root_ca.crt" = local.ca_bundle
  }
}

resource "kubernetes_secret" "remote-ca-cert" {
  count = var.ebpf_only == false && var.remote_ca_bundle != "" ? 1 : 0
  metadata {
    name        = local.remote_tls_ca_cert_secret_name
    namespace   = var.namespace
    labels      = local.labels
    annotations = var.additional_global_annotations
  }
  type = "Opaque"
  data = {
    # Need to base64decode since terraform will re-encode it.
    "ca_cert.crt" = base64decode(var.remote_ca_bundle)
  }
}

resource "kubernetes_secret" "mtls_secret" {
  count = var.ebpf_only == false && var.remote_client_cert != "" && var.remote_client_key != "" ? 1 : 0
  metadata {
    name        = local.mtls_cert_key_secret_name
    namespace   = var.namespace
    labels      = local.labels
    annotations = var.additional_global_annotations
  }
  type = "Opaque"
  data = {
    "client-cert.pem" = base64decode(var.remote_client_cert)
    "client-key.pem"  = base64decode(var.remote_client_key)
  }
}

resource "kubernetes_secret" "tpa-client-ca-cert" {
  count = var.ebpf_only == true && var.tpa_ca_bundle != "" ? 1 : 0
  metadata {
    name        = local.tpa_tls_ca_cert_for_clients_secret_name
    namespace   = var.namespace
    labels      = local.labels
    annotations = var.additional_global_annotations
  }
  type = "Opaque"
  data = {
    # Need to base64decode since terraform will re-encode it.
    "ca_cert.crt" = base64decode(var.tpa_ca_bundle)
  }
}


resource "kubernetes_secret" "tls-private-keys-string" {
  count = var.ebpf_only == false && local.tls_certs_as_strings_enabled == true ? 1 : 0
  metadata {
    name        = local.cert_secret_name
    namespace   = var.namespace
    labels      = local.labels
    annotations = var.additional_global_annotations
  }
  type = "Opaque"
  data = {
    "tls.key"     = base64decode(var.tls_private_certificates_as_strings.key_b64)
    "tls.crt"     = base64decode(var.tls_private_certificates_as_strings.cert_b64)
    "root_ca.crt" = base64decode(var.tls_private_certificates_as_strings.root_ca_b64)
  }
}
