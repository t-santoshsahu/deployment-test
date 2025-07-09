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
  # Default is 365 days (365*24=8670)
  default = 8760
}

variable "ca_common_name" {
  description = "The common name to use in the subject of the CA certificate (e.g. acme.co cert)."
  type        = string
  default     = "example.com"
}

variable "organization_name" {
  description = "The name of the organization to associate with the certificates (e.g. Acme Co)."
  type        = string
  default     = "Example Organization"
}

variable "ca_allowed_uses" {
  description = "List of keywords from RFC5280 describing a use that is permitted for the CA certificate. For more info and the list of keywords, see https://www.terraform.io/docs/providers/tls/r/self_signed_cert.html#allowed_uses."
  type        = list(string)

  default = [
    "cert_signing",
    "key_encipherment",
    "digital_signature",
  ]
}
