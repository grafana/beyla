resource "aws_ecr_repository" "app" {
  for_each = toset(["catalog", "checkout", "legacy-api", "storefront"])

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
      image = "${aws_ecr_repository.app["checkout"].repository_url}:3"
      environment = [
        {
          name  = "LEGACY_URL"
          value = "http://${var.legacy_ip}:8083/legacy"
        },
        {
          name  = "DB_HOST"
          value = aws_db_instance.orders.address
        },
        {
          name  = "DB_NAME"
          value = aws_db_instance.orders.db_name
        },
      ]
      secrets = [{
        name      = "DB_SECRET"
        valueFrom = aws_db_instance.orders.master_user_secret[0].secret_arn
      }]
      portMappings = [{
        containerPort = 8080
        hostPort      = 8080
        protocol      = "tcp"
      }]
    })
  ])

  lifecycle {
    precondition {
      condition     = var.legacy_ip != ""
      error_message = "legacy_ip must be set when deploy_checkout is true."
    }
  }
}

resource "aws_ecs_service" "checkout" {
  count = var.deploy_checkout ? 1 : 0

  name                  = "checkout"
  cluster               = aws_ecs_cluster.backend.id
  task_definition       = aws_ecs_task_definition.checkout[0].arn
  desired_count         = 1
  launch_type           = "EC2"
  wait_for_steady_state = true

  network_configuration {
    subnets          = [aws_subnet.backend_host.id]
    security_groups  = [aws_security_group.backend.id]
    assign_public_ip = false
  }

  placement_constraints {
    type       = "memberOf"
    expression = "attribute:poc.role == checkout"
  }

  depends_on = [aws_instance.ecs, aws_iam_role_policy.task_database_secret]
}

resource "aws_ecs_task_definition" "legacy" {
  count = var.deploy_legacy ? 1 : 0

  family                   = "${var.name}-legacy-api"
  requires_compatibilities = ["EC2"]
  network_mode             = "awsvpc"
  cpu                      = 128
  memory                   = 128
  execution_role_arn       = aws_iam_role.task_execution.arn

  container_definitions = jsonencode([
    merge(local.common_container, {
      name  = "legacy-api"
      image = "${aws_ecr_repository.app["legacy-api"].repository_url}:1"
      portMappings = [{
        containerPort = 8083
        hostPort      = 8083
        protocol      = "tcp"
      }]
    })
  ])
}

resource "aws_ecs_service" "legacy" {
  count = var.deploy_legacy ? 1 : 0

  name                  = "legacy-api"
  cluster               = aws_ecs_cluster.backend.id
  task_definition       = aws_ecs_task_definition.legacy[0].arn
  desired_count         = 1
  launch_type           = "EC2"
  wait_for_steady_state = true

  network_configuration {
    subnets          = [aws_subnet.backend_host.id]
    security_groups  = [aws_security_group.backend.id]
    assign_public_ip = false
  }

  placement_constraints {
    type       = "memberOf"
    expression = "attribute:poc.role == checkout"
  }

  depends_on = [aws_instance.ecs]
}

resource "aws_ecs_task_definition" "catalog" {
  count = var.checkout_ip != "" ? 1 : 0

  family                   = "${var.name}-catalog"
  requires_compatibilities = ["EC2"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 256
  execution_role_arn       = aws_iam_role.task_execution.arn

  container_definitions = jsonencode([
    merge(local.common_container, {
      name  = "catalog"
      image = "${aws_ecr_repository.app["catalog"].repository_url}:1"
      environment = [{
        name  = "CHECKOUT_URL"
        value = "http://${var.checkout_ip}:8080/checkout"
      }]
      portMappings = [{
        containerPort = 8082
        hostPort      = 8082
        protocol      = "tcp"
      }]
    })
  ])
}

resource "aws_ecs_service" "catalog" {
  count = var.checkout_ip != "" ? 1 : 0

  name                  = "catalog"
  cluster               = aws_ecs_cluster.poc.id
  task_definition       = aws_ecs_task_definition.catalog[0].arn
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

resource "aws_ecs_task_definition" "storefront" {
  count = var.catalog_ip != "" ? 1 : 0

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
        name  = "CATALOG_URL"
        value = "http://${var.catalog_ip}:8082/catalog"
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
  count = var.catalog_ip != "" ? 1 : 0

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
