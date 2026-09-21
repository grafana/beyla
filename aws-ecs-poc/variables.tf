variable "aws_profile" {
  description = "AWS CLI profile used by the provider."
  type        = string
  default     = "sandbox"
}

variable "aws_region" {
  description = "AWS region for the PoC."
  type        = string
  default     = "us-east-2"
}

variable "name" {
  description = "Prefix used for PoC resources."
  type        = string
  default     = "beyla-nonk8s-poc"
}

variable "owner" {
  description = "Owner tag used to identify the person responsible for cleanup."
  type        = string
}

variable "expires" {
  description = "Expiry tag in YYYY-MM-DD format."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}$", var.expires))
    error_message = "expires must use YYYY-MM-DD format."
  }
}

variable "vpc_id" {
  description = "VPC to use. Leave empty to use the region's default VPC."
  type        = string
  default     = ""
}

variable "subnet_id" {
  description = "Subnet for hosts and task ENIs. Leave empty to select the first subnet in the VPC."
  type        = string
  default     = ""
}

variable "backend_vpc_cidr" {
  description = "CIDR for the peered backend and database VPC. It must not overlap the frontend VPC."
  type        = string
  default     = "10.42.0.0/16"
}

variable "instance_type" {
  description = "EC2 instance type used for each ECS container instance."
  type        = string
  default     = "t3.small"
}

variable "beyla_version" {
  description = "Standalone Beyla release installed on each ECS host."
  type        = string
  default     = "v3.35.0"
}

variable "deploy_checkout" {
  description = "Create the checkout ECS service after its image has been pushed."
  type        = bool
  default     = false
}

variable "deploy_legacy" {
  description = "Create the legacy ECS service without Beyla instrumentation."
  type        = bool
  default     = false
}

variable "legacy_ip" {
  description = "Private IP of the running legacy task. Checkout calls this literal address."
  type        = string
  default     = ""

  validation {
    condition     = var.legacy_ip == "" || can(cidrhost("${var.legacy_ip}/32", 0))
    error_message = "legacy_ip must be empty or a valid IPv4 address."
  }
}

variable "checkout_ip" {
  description = "Private IP of the running checkout task. Setting it creates the catalog service."
  type        = string
  default     = ""

  validation {
    condition     = var.checkout_ip == "" || can(cidrhost("${var.checkout_ip}/32", 0))
    error_message = "checkout_ip must be empty or a valid IPv4 address."
  }
}

variable "catalog_ip" {
  description = "Private IP of the running catalog task. Setting it creates the storefront service."
  type        = string
  default     = ""

  validation {
    condition     = var.catalog_ip == "" || can(cidrhost("${var.catalog_ip}/32", 0))
    error_message = "catalog_ip must be empty or a valid IPv4 address."
  }
}
