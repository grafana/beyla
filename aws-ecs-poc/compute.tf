data "aws_ssm_parameter" "ecs_ami" {
  name = "/aws/service/ecs/optimized-ami/amazon-linux-2023/recommended/image_id"
}

resource "aws_ecs_cluster" "poc" {
  name = var.name
}

locals {
  hosts = {
    caller   = "caller"
    checkout = "checkout"
  }
}

resource "aws_instance" "ecs" {
  for_each = local.hosts

  ami                         = data.aws_ssm_parameter.ecs_ami.value
  instance_type               = var.instance_type
  subnet_id                   = local.subnet_id
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.poc.id]
  iam_instance_profile        = aws_iam_instance_profile.ecs_instance.name

  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/templates/user-data.sh.tftpl", {
    cluster_name  = aws_ecs_cluster.poc.name
    host_role     = each.value
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
    Role = each.value
  }

  depends_on = [
    aws_iam_role_policy_attachment.ecs_instance,
    aws_iam_role_policy_attachment.ssm,
    aws_iam_role_policy.inventory,
  ]
}
