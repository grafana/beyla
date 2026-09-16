output "cluster_name" {
  value = aws_ecs_cluster.poc.name
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

output "instance_ids" {
  value = { for role, instance in aws_instance.ecs : role => instance.id }
}

output "ecr_repository_urls" {
  value = { for app, repository in aws_ecr_repository.app : app => repository.repository_url }
}
