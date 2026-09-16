data "aws_vpc" "default" {
  count   = var.vpc_id == "" ? 1 : 0
  default = true
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
  to_port                      = 8081
}

resource "aws_vpc_security_group_egress_rule" "all" {
  security_group_id = aws_security_group.poc.id
  description       = "Allow package, image, SSM, and telemetry traffic"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}
