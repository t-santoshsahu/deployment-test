resource "tls_private_key" "ca" {
  algorithm   = var.private_key_algorithm
  rsa_bits    = var.private_key_rsa_bits
  ecdsa_curve = var.private_key_ecdsa_curve
}

resource "tls_self_signed_cert" "ca" {
  private_key_pem       = tls_private_key.ca.private_key_pem
  is_ca_certificate     = true
  validity_period_hours = var.validity_period_hours
  allowed_uses          = var.ca_allowed_uses

  subject {
    common_name  = var.ca_common_name
    organization = var.organization_name
  }
}
