# Security baseline for running Patchwarden-managed workloads in a customer's Azure subscription.
# Validated in CI with `terraform validate` + Checkov. Never applied by CI: applying costs money.
# Inline `checkov:skip` comments document every control intentionally not met, and why.

terraform {
  required_version = ">= 1.6"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
}

provider "azurerm" {
  features {}
}

data "azurerm_client_config" "current" {}

resource "azurerm_resource_group" "rg" {
  name     = "${var.prefix}-rg"
  location = var.location
  tags     = var.tags
}

# ---------------------------------------------------------------- logging

resource "azurerm_log_analytics_workspace" "logs" {
  name                = "${var.prefix}-logs"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  sku                 = "PerGB2018"
  retention_in_days   = 90
  tags                = var.tags
}

# ---------------------------------------------------------------- identity

# One user-assigned identity per workload; no shared secrets, no admin users.
resource "azurerm_user_assigned_identity" "aks" {
  name                = "${var.prefix}-aks-id"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  tags                = var.tags
}

# ---------------------------------------------------------------- network

resource "azurerm_virtual_network" "vnet" {
  name                = "${var.prefix}-vnet"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  address_space       = ["10.20.0.0/16"]
  tags                = var.tags
}

resource "azurerm_subnet" "aks" {
  name                 = "aks"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = ["10.20.0.0/22"]
}

resource "azurerm_network_security_group" "aks" {
  name                = "${var.prefix}-aks-nsg"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  tags                = var.tags
  # No inbound allow rules: the API server is private and workloads are reached through internal LBs.
}

resource "azurerm_subnet_network_security_group_association" "aks" {
  subnet_id                 = azurerm_subnet.aks.id
  network_security_group_id = azurerm_network_security_group.aks.id
}

# ---------------------------------------------------------------- registry

resource "azurerm_container_registry" "acr" {
  #checkov:skip=CKV_AZURE_165:Geo-replication needs Premium SKU; out of scope for a $0 reference baseline
  #checkov:skip=CKV_AZURE_233:Zone redundancy needs Premium SKU; out of scope for a $0 reference baseline
  #checkov:skip=CKV_AZURE_237:Dedicated data endpoints need Premium SKU
  #checkov:skip=CKV_AZURE_164:Trusted (content-trust) images superseded by cosign signatures enforced at admission
  #checkov:skip=CKV_AZURE_166:Quarantine needs Premium SKU; images are gated by Patchwarden verify + cosign instead
  #checkov:skip=CKV_AZURE_167:Retention policy needs Premium SKU
  #checkov:skip=CKV_AZURE_139:Private-only network access needs Premium SKU; set var.acr_sku = "Premium" in production
  name                          = replace("${var.prefix}acr", "-", "")
  location                      = azurerm_resource_group.rg.location
  resource_group_name           = azurerm_resource_group.rg.name
  sku                           = var.acr_sku
  admin_enabled                 = false # identities only, no shared admin password
  public_network_access_enabled = var.acr_sku == "Premium" ? false : true
  tags                          = var.tags
}

# AKS pulls with its kubelet identity; nothing else gets push rights.
resource "azurerm_role_assignment" "aks_pull" {
  scope                = azurerm_container_registry.acr.id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_kubernetes_cluster.aks.kubelet_identity[0].object_id
}

# ---------------------------------------------------------------- secrets

resource "azurerm_key_vault" "kv" {
  #checkov:skip=CKV_AZURE_189:Public access kept on with deny-by-default ACLs for the reference baseline; use a private endpoint in production
  #checkov:skip=CKV2_AZURE_32:Private endpoint omitted in the $0 reference baseline
  name                          = "${var.prefix}-kv"
  location                      = azurerm_resource_group.rg.location
  resource_group_name           = azurerm_resource_group.rg.name
  tenant_id                     = data.azurerm_client_config.current.tenant_id
  sku_name                      = "premium"
  rbac_authorization_enabled    = true
  purge_protection_enabled      = true
  soft_delete_retention_days    = 90
  public_network_access_enabled = true
  tags                          = var.tags

  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
    ip_rules       = var.admin_ip_ranges
  }
}

# ---------------------------------------------------------------- kubernetes

resource "azurerm_kubernetes_cluster" "aks" {
  #checkov:skip=CKV_AZURE_170:Paid SLA tier is a cost decision; enable sku_tier = "Standard" in production
  #checkov:skip=CKV_AZURE_117:Customer-managed disk encryption set omitted in the reference baseline (platform-managed keys)
  #checkov:skip=CKV_AZURE_6:API server is private (CKV_AZURE_115), so authorized IP ranges do not apply
  name                              = "${var.prefix}-aks"
  location                          = azurerm_resource_group.rg.location
  resource_group_name               = azurerm_resource_group.rg.name
  dns_prefix                        = "${var.prefix}-aks"
  kubernetes_version                = var.kubernetes_version
  automatic_upgrade_channel         = "patch"
  node_os_upgrade_channel           = "NodeImage"
  private_cluster_enabled           = true
  local_account_disabled            = true
  role_based_access_control_enabled = true
  azure_policy_enabled              = true
  oidc_issuer_enabled               = true
  workload_identity_enabled         = true
  tags                              = var.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.aks.id]
  }

  azure_active_directory_role_based_access_control {
    azure_rbac_enabled = true
    tenant_id          = data.azurerm_client_config.current.tenant_id
  }

  default_node_pool {
    name                         = "system"
    vm_size                      = var.node_vm_size
    node_count                   = 2
    max_pods                     = 50
    os_disk_type                 = "Ephemeral"
    host_encryption_enabled      = true
    only_critical_addons_enabled = true
    vnet_subnet_id               = azurerm_subnet.aks.id
    upgrade_settings {
      max_surge = "33%"
    }
  }

  network_profile {
    network_plugin = "azure"
    network_policy = "azure" # default-deny NetworkPolicies are enforceable
  }

  oms_agent {
    log_analytics_workspace_id = azurerm_log_analytics_workspace.logs.id
  }

  key_vault_secrets_provider {
    secret_rotation_enabled = true
  }

  microsoft_defender {
    log_analytics_workspace_id = azurerm_log_analytics_workspace.logs.id
  }
}
