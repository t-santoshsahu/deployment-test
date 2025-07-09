resource "tls_private_key" "cert" {
  algorithm   = var.private_key_algorithm
  ecdsa_curve = var.private_key_ecdsa_curve
  rsa_bits    = var.private_key_rsa_bits
}

resource "tls_cert_request" "cert" {
  private_key_pem = tls_private_key.cert.private_key_pem

  dns_names = var.dns_names

  subject {
    common_name  = var.common_name
    organization = var.organization_name
  }
}

resource "tls_locally_signed_cert" "cert" {
  cert_request_pem = tls_cert_request.cert.cert_request_pem

  ca_private_key_pem = var.ca_private_key_pem
  ca_cert_pem        = var.ca_cert_pem

  validity_period_hours = var.validity_period_hours
  allowed_uses          = var.allowed_uses
}
