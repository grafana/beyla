resource "aws_ecr_repository" "app" {
  for_each = toset(["checkout", "storefront"])

  name                 = "${var.name}-${each.key}"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_cloudwatch_log_group" "poc" {
  name              = "/ecs/${var.name}"
  retention_in_days = 7
}

locals {
  common_container = {
    essential = true
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.poc.name
        awslogs-region        = var.aws_region
        awslogs-stream-prefix = "app"
      }
    }
  }
}

resource "aws_ecs_task_definition" "checkout" {
  count = var.deploy_checkout ? 1 : 0

  family                   = "${var.name}-checkout"
  requires_compatibilities = ["EC2"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 256
  execution_role_arn       = aws_iam_role.task_execution.arn

  container_definitions = jsonencode([
    merge(local.common_container, {
      name  = "checkout"
      image = "${aws_ecr_repository.app["checkout"].repository_url}:2"
      portMappings = [{
        containerPort = 8080
        hostPort      = 8080
        protocol      = "tcp"
      }]
    })
  ])
}

resource "aws_ecs_service" "checkout" {
  count = var.deploy_checkout ? 1 : 0

  name                  = "checkout"
  cluster               = aws_ecs_cluster.poc.id
  task_definition       = aws_ecs_task_definition.checkout[0].arn
  desired_count         = 1
  launch_type           = "EC2"
  wait_for_steady_state = true

  network_configuration {
    subnets          = [local.subnet_id]
    security_groups  = [aws_security_group.poc.id]
    assign_public_ip = false
  }

  placement_constraints {
    type       = "memberOf"
    expression = "attribute:poc.role == checkout"
  }

  depends_on = [aws_instance.ecs]
}

resource "aws_ecs_task_definition" "storefront" {
  count = var.checkout_ip != "" ? 1 : 0

  family                   = "${var.name}-storefront"
  requires_compatibilities = ["EC2"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 256
  execution_role_arn       = aws_iam_role.task_execution.arn

  container_definitions = jsonencode([
    merge(local.common_container, {
      name  = "storefront"
      image = "${aws_ecr_repository.app["storefront"].repository_url}:1"
      environment = [{
        name  = "CHECKOUT_URL"
        value = "http://${var.checkout_ip}:8080/checkout"
      }]
      portMappings = [{
        containerPort = 8081
        hostPort      = 8081
        protocol      = "tcp"
      }]
    })
  ])
}

resource "aws_ecs_service" "storefront" {
  count = var.checkout_ip != "" ? 1 : 0

  name                  = "storefront"
  cluster               = aws_ecs_cluster.poc.id
  task_definition       = aws_ecs_task_definition.storefront[0].arn
  desired_count         = 1
  launch_type           = "EC2"
  wait_for_steady_state = true

  network_configuration {
    subnets          = [local.subnet_id]
    security_groups  = [aws_security_group.poc.id]
    assign_public_ip = false
  }

  placement_constraints {
    type       = "memberOf"
    expression = "attribute:poc.role == caller"
  }

  depends_on = [aws_instance.ecs]
}
