output "cluster_name" {
  value = aws_ecs_cluster.poc.name
}

output "cluster_names" {
  value = {
    frontend = aws_ecs_cluster.poc.name
    backend  = aws_ecs_cluster.backend.name
  }
}

output "vpc_id" {
  value = local.vpc_id
}

output "subnet_id" {
  value = local.subnet_id
}

output "security_group_id" {
  value = aws_security_group.poc.id
}

output "backend_vpc_id" {
  value = aws_vpc.backend.id
}

output "database_endpoint" {
  value = aws_db_instance.orders.endpoint
}

output "instance_ids" {
  value = { for role, instance in aws_instance.ecs : role => instance.id }
}

output "ecr_repository_urls" {
  value = { for app, repository in aws_ecr_repository.app : app => repository.repository_url }
}
