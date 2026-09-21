resource "aws_security_group" "database" {
  name        = "${var.name}-database"
  description = "PostgreSQL access from the backend ECS tasks"
  vpc_id      = aws_vpc.backend.id
}

resource "aws_vpc_security_group_egress_rule" "database" {
  security_group_id = aws_security_group.database.id
  description       = "Allow database response traffic"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_ingress_rule" "database" {
  security_group_id            = aws_security_group.database.id
  referenced_security_group_id = aws_security_group.backend.id
  description                  = "Allow checkout to query PostgreSQL"
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
}

resource "aws_db_subnet_group" "orders" {
  name       = "${var.name}-orders"
  subnet_ids = [for subnet in aws_subnet.database : subnet.id]

  tags = {
    Name = "${var.name}-orders"
  }
}

resource "aws_db_parameter_group" "orders" {
  name   = "${var.name}-orders"
  family = "postgres14"

  parameter {
    name         = "rds.force_ssl"
    value        = "0"
    apply_method = "immediate"
  }
}

resource "aws_db_instance" "orders" {
  identifier = "${var.name}-orders"

  engine         = "postgres"
  engine_version = "14.24"
  instance_class = "db.t4g.micro"

  allocated_storage = 20
  storage_type      = "gp3"
  storage_encrypted = true

  db_name                     = "orders"
  username                    = "poc"
  manage_master_user_password = true
  port                        = 5432

  db_subnet_group_name   = aws_db_subnet_group.orders.name
  parameter_group_name   = aws_db_parameter_group.orders.name
  vpc_security_group_ids = [aws_security_group.database.id]
  publicly_accessible    = false
  multi_az               = false

  backup_retention_period = 0
  deletion_protection     = false
  skip_final_snapshot     = true
  apply_immediately       = true
}
