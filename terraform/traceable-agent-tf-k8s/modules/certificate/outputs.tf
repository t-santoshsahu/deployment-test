output "cert_private_key_pem" {
  value = tls_private_key.cert.private_key_pem
}

output "cert_public_key_pem" {
  value = tls_locally_signed_cert.cert.cert_pem
}
