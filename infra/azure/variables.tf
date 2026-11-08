variable "prefix" {
  description = "Short name prefix for all resources (lowercase letters, digits, dashes)."
  type        = string
  default     = "patchwarden"
}

variable "location" {
  type    = string
  default = "eastus2"
}

variable "acr_sku" {
  description = "Basic/Standard for demos; Premium unlocks private networking, quarantine and retention."
  type        = string
  default     = "Standard"
  validation {
    condition     = contains(["Basic", "Standard", "Premium"], var.acr_sku)
    error_message = "acr_sku must be Basic, Standard or Premium."
  }
}

variable "kubernetes_version" {
  type    = string
  default = null # latest supported by AKS
}

variable "node_vm_size" {
  type    = string
  default = "Standard_D4ds_v5" # supports ephemeral OS disks and host encryption
}

variable "admin_ip_ranges" {
  description = "CIDRs allowed through the Key Vault firewall."
  type        = list(string)
  default     = []
}

variable "tags" {
  type = map(string)
  default = {
    project    = "patchwarden"
    managed-by = "terraform"
  }
}
