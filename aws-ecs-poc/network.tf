data "aws_vpc" "default" {
  count   = var.vpc_id == "" ? 1 : 0
  default = true
}

data "aws_vpc" "selected" {
  id = local.vpc_id
}

data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  vpc_id = var.vpc_id != "" ? var.vpc_id : data.aws_vpc.default[0].id
}

data "aws_subnets" "selected_vpc" {
  filter {
    name   = "vpc-id"
    values = [local.vpc_id]
  }
}

locals {
  subnet_id = var.subnet_id != "" ? var.subnet_id : sort(data.aws_subnets.selected_vpc.ids)[0]
}

data "aws_route_table" "frontend" {
  vpc_id = local.vpc_id

  filter {
    name   = "association.main"
    values = ["true"]
  }
}

resource "aws_security_group" "poc" {
  name        = var.name
  description = "Direct task traffic for the Beyla non-Kubernetes PoC"
  vpc_id      = local.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "application" {
  security_group_id            = aws_security_group.poc.id
  referenced_security_group_id = aws_security_group.poc.id
  description                  = "Allow direct application traffic between PoC hosts and task ENIs"
  ip_protocol                  = "tcp"
  from_port                    = 8080
  to_port                      = 8082
}

resource "aws_vpc_security_group_egress_rule" "all" {
  security_group_id = aws_security_group.poc.id
  description       = "Allow package, image, SSM, and telemetry traffic"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc" "backend" {
  cidr_block           = var.backend_vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${var.name}-backend"
  }
}

resource "aws_internet_gateway" "backend" {
  vpc_id = aws_vpc.backend.id

  tags = {
    Name = "${var.name}-backend"
  }
}

resource "aws_subnet" "backend_host" {
  vpc_id                  = aws_vpc.backend.id
  cidr_block              = cidrsubnet(var.backend_vpc_cidr, 8, 0)
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.name}-backend-host"
  }
}

locals {
  database_subnets = {
    a = {
      cidr = cidrsubnet(var.backend_vpc_cidr, 8, 10)
      az   = data.aws_availability_zones.available.names[0]
    }
    b = {
      cidr = cidrsubnet(var.backend_vpc_cidr, 8, 11)
      az   = data.aws_availability_zones.available.names[1]
    }
  }
}

resource "aws_subnet" "database" {
  for_each = local.database_subnets

  vpc_id            = aws_vpc.backend.id
  cidr_block        = each.value.cidr
  availability_zone = each.value.az

  tags = {
    Name = "${var.name}-database-${each.key}"
  }
}

resource "aws_route_table" "backend_host" {
  vpc_id = aws_vpc.backend.id

  tags = {
    Name = "${var.name}-backend-host"
  }
}

resource "aws_route" "backend_internet" {
  route_table_id         = aws_route_table.backend_host.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.backend.id
}

resource "aws_route_table_association" "backend_host" {
  subnet_id      = aws_subnet.backend_host.id
  route_table_id = aws_route_table.backend_host.id
}

resource "aws_route_table" "database" {
  vpc_id = aws_vpc.backend.id

  tags = {
    Name = "${var.name}-database"
  }
}

resource "aws_route_table_association" "database" {
  for_each = aws_subnet.database

  subnet_id      = each.value.id
  route_table_id = aws_route_table.database.id
}

resource "aws_vpc_peering_connection" "frontend_backend" {
  vpc_id      = local.vpc_id
  peer_vpc_id = aws_vpc.backend.id
  auto_accept = true

  tags = {
    Name = "${var.name}-frontend-backend"
  }
}

resource "aws_route" "frontend_to_backend" {
  route_table_id            = data.aws_route_table.frontend.id
  destination_cidr_block    = aws_vpc.backend.cidr_block
  vpc_peering_connection_id = aws_vpc_peering_connection.frontend_backend.id
}

resource "aws_route" "backend_to_frontend" {
  route_table_id            = aws_route_table.backend_host.id
  destination_cidr_block    = data.aws_vpc.selected.cidr_block
  vpc_peering_connection_id = aws_vpc_peering_connection.frontend_backend.id
}

resource "aws_security_group" "backend" {
  name        = "${var.name}-backend"
  description = "Backend ECS tasks and host"
  vpc_id      = aws_vpc.backend.id
}

resource "aws_vpc_security_group_ingress_rule" "backend_checkout" {
  security_group_id = aws_security_group.backend.id
  description       = "Allow checkout traffic from the frontend VPC"
  cidr_ipv4         = data.aws_vpc.selected.cidr_block
  ip_protocol       = "tcp"
  from_port         = 8080
  to_port           = 8080
}

resource "aws_vpc_security_group_ingress_rule" "backend_legacy" {
  security_group_id            = aws_security_group.backend.id
  referenced_security_group_id = aws_security_group.backend.id
  description                  = "Allow checkout to call the uninstrumented legacy service"
  ip_protocol                  = "tcp"
  from_port                    = 8083
  to_port                      = 8083
}

resource "aws_vpc_security_group_egress_rule" "backend" {
  security_group_id = aws_security_group.backend.id
  description       = "Allow AWS APIs, package downloads, telemetry, and application traffic"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}
