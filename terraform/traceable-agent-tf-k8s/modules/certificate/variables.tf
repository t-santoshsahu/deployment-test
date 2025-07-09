variable "private_key_algorithm" {
  description = "The name of the algorithm to use for private keys. Must be one of: RSA or ECDSA."
  type        = string
  default     = "RSA"
}

variable "private_key_rsa_bits" {
  description = "The size of the generated RSA key in bits. Should only be used if var.private_key_algorithm is RSA."
  type        = number
  default     = 2048
}

variable "private_key_ecdsa_curve" {
  description = "The name of the elliptic curve to use. Should only be used if var.private_key_algorithm is ECDSA. Must be one of P224, P256, P384 or P521."
  type        = string
  default     = "P224"
}

variable "validity_period_hours" {
  description = "The number of hours after initial issuing that the certificate will become invalid."
  type        = number
  default     = 8760
}

variable "organization_name" {
  description = "The name of the organization to associate with the certificates (e.g. Acme Co)."
  type        = string
  default     = "Traceable AI, Inc"
}

variable "common_name" {
  description = "The common name to use in the subject of the certificate (e.g. acme.co cert)."
  type        = string
}

variable "dns_names" {
  description = "List of DNS names for which the certificate will be valid (e.g. foo.example.com)."
  type        = list(string)
}

variable "ca_key_algorithm" {
  description = "The name of Algorithm used for CA key"
  type        = string
}

variable "ca_private_key_pem" {
  description = "Private key pem of CA"
  type        = string
}

variable "allowed_uses" {
  description = "List of keywords from RFC5280 describing a use that is permitted for the issued certificate. For more info and the list of keywords, see https://www.terraform.io/docs/providers/tls/r/self_signed_cert.html#allowed_uses."
  type        = list(string)

  default = [
    "key_encipherment",
    "digital_signature",
  ]
}

variable "ca_cert_pem" {
  description = "Cert PEM of CA"
  type        = string
}
