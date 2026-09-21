data "aws_ssm_parameter" "ecs_ami" {
  name = "/aws/service/ecs/optimized-ami/amazon-linux-2023/recommended/image_id"
}

resource "aws_ecs_cluster" "poc" {
  name = var.name
}

resource "aws_ecs_cluster" "backend" {
  name = "${var.name}-backend"
}

locals {
  hosts = {
    caller = {
      role               = "caller"
      cluster_name       = aws_ecs_cluster.poc.name
      subnet_id          = local.subnet_id
      security_group_ids = [aws_security_group.poc.id]
    }
    checkout = {
      role               = "checkout"
      cluster_name       = aws_ecs_cluster.backend.name
      subnet_id          = aws_subnet.backend_host.id
      security_group_ids = [aws_security_group.backend.id]
    }
  }
}

resource "aws_instance" "ecs" {
  for_each = local.hosts

  ami                         = data.aws_ssm_parameter.ecs_ami.value
  instance_type               = var.instance_type
  subnet_id                   = each.value.subnet_id
  associate_public_ip_address = true
  vpc_security_group_ids      = each.value.security_group_ids
  iam_instance_profile        = aws_iam_instance_profile.ecs_instance.name

  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/templates/user-data.sh.tftpl", {
    cluster_name  = each.value.cluster_name
    host_role     = each.value.role
    beyla_version = var.beyla_version
  })

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  root_block_device {
    volume_type = "gp3"
    volume_size = 30
    encrypted   = true
  }

  tags = {
    Name = "${var.name}-${each.key}"
    Role = each.value.role
  }

  depends_on = [
    aws_iam_role_policy_attachment.ecs_instance,
    aws_iam_role_policy_attachment.ssm,
    aws_iam_role_policy.inventory,
  ]
}
