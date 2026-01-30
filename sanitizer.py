#!/usr/bin/env python3
"""
tf-sanitizer - Extract diagram-relevant data from Terraform state JSON

Removes all sensitive data (ARNs, IDs, secrets, IPs) and keeps only what's 
needed for architecture diagrams.

Usage:
    terraform show -json > raw.json
    python sanitizer.py raw.json clean.json
    
    Or pipe directly:
    terraform show -json | python sanitizer.py - clean.json

Input:  Raw terraform show -json output (contains secrets)
Output: Clean JSON with only diagram-relevant data (safe to commit)
"""

import json
import sys
from pathlib import Path


# Resources to include in diagrams
DIAGRAM_RESOURCES = {
    # Compute
    "aws_instance",
    "aws_launch_template",
    "aws_launch_configuration",
    "aws_spot_instance_request",
    "aws_autoscaling_group",
    "aws_autoscaling_policy",
    "aws_lambda_function",
    "aws_lambda_function_url",
    "aws_lambda_alias",
    "aws_lambda_layer_version",
    "aws_elastic_beanstalk_environment",
    "aws_elastic_beanstalk_application",
    
    # Containers
    "aws_ecs_cluster",
    "aws_ecs_service",
    "aws_ecs_task_definition",
    "aws_ecr_repository",
    "aws_eks_cluster",
    "aws_eks_node_group",
    "aws_eks_fargate_profile",
    
    # Database
    "aws_db_instance",
    "aws_db_cluster",
    "aws_rds_cluster",
    "aws_rds_cluster_instance",
    "aws_rds_proxy",
    "aws_dynamodb_table",
    "aws_dynamodb_global_table",
    "aws_elasticache_cluster",
    "aws_elasticache_replication_group",
    "aws_redshift_cluster",
    "aws_docdb_cluster",
    "aws_neptune_cluster",
    
    # Storage
    "aws_s3_bucket",
    "aws_efs_file_system",
    "aws_ebs_volume",
    "aws_fsx_lustre_file_system",
    "aws_fsx_windows_file_system",
    "aws_glacier_vault",
    "aws_backup_vault",
    "aws_backup_plan",
    "aws_storagegateway_gateway",
    
    # Networking
    "aws_vpc",
    "aws_internet_gateway",
    "aws_nat_gateway",
    "aws_vpn_gateway",
    "aws_customer_gateway",
    "aws_vpc_peering_connection",
    "aws_vpc_endpoint",
    "aws_transit_gateway",
    "aws_route53_zone",
    "aws_cloudfront_distribution",
    "aws_lb",
    "aws_alb",
    "aws_elb",
    "aws_api_gateway_rest_api",
    "aws_apigatewayv2_api",
    "aws_appsync_graphql_api",
    "aws_direct_connect_gateway",
    "aws_dx_connection",
    
    # Security & Identity
    "aws_iam_role",
    "aws_acm_certificate",
    "aws_secretsmanager_secret",
    "aws_ssm_parameter",
    "aws_kms_key",
    "aws_wafv2_web_acl",
    "aws_waf_web_acl",
    "aws_wafregional_web_acl",
    "aws_shield_protection",
    "aws_cognito_user_pool",
    "aws_cognito_identity_pool",
    
    # Application Integration
    "aws_sqs_queue",
    "aws_sns_topic",
    "aws_sfn_state_machine",
    "aws_cloudwatch_event_rule",
    "aws_scheduler_schedule",
    "aws_mq_broker",
    "aws_msk_cluster",
    "aws_ses_domain_identity",
    "aws_ses_email_identity",
    
    # Analytics
    "aws_kinesis_stream",
    "aws_kinesis_firehose_delivery_stream",
    "aws_athena_database",
    "aws_athena_workgroup",
    "aws_glue_catalog_database",
    "aws_glue_catalog_table",
    "aws_glue_job",
    "aws_glue_crawler",
    "aws_emr_cluster",
    "aws_opensearch_domain",
    "aws_elasticsearch_domain",
    "aws_quicksight_data_source",
    "aws_lakeformation_resource",
    
    # Management & Monitoring
    "aws_cloudwatch_log_group",
    "aws_cloudwatch_metric_alarm",
    "aws_cloudwatch_dashboard",
    "aws_cloudformation_stack",
    "aws_cloudtrail",
    "aws_config_config_rule",
    "aws_ssm_document",
    "aws_ssm_maintenance_window",
    "aws_organizations_organization",
    "aws_organizations_account",
    
    # AI/ML
    "aws_sagemaker_endpoint",
    "aws_sagemaker_model",
    "aws_sagemaker_notebook_instance",
    "aws_sagemaker_training_job",
    "aws_bedrock_custom_model",
    "aws_rekognition_collection",
    
    # IoT
    "aws_iot_thing",
    "aws_iot_topic_rule",
    "aws_iot_policy",
    "aws_greengrass_group",
    
    # Developer Tools
    "aws_codecommit_repository",
    "aws_codebuild_project",
    "aws_codepipeline",
    "aws_codedeploy_app",
    "aws_amplify_app",
}

# Attributes safe to extract (no secrets)
SAFE_ATTRIBUTES = {
    "name",
    "bucket",
    "function_name",
    "cluster_name",
    "domain_name",
    "description",
    "vpc_id",
    "subnet_id", 
    "subnet_ids",
    "availability_zone",
    "availability_zones",
    "tags",
    "tags_all",
}


def extract_label(resource):
    """Extract a human-readable label for the resource."""
    values = resource.get("values", {})
    
    # Priority: tags.Name > name attribute > resource name
    tags = values.get("tags") or values.get("tags_all") or {}
    if isinstance(tags, dict) and tags.get("Name"):
        return tags["Name"]
    
    # Try common name attributes
    for attr in ["name", "bucket", "function_name", "cluster_name", "domain_name"]:
        if values.get(attr):
            return values[attr]
    
    # Fall back to resource name from address
    return resource.get("name", "unknown")


def extract_module_name(address):
    """Extract module name from resource address."""
    if address.startswith("module."):
        parts = address.split(".")
        if len(parts) >= 2:
            return parts[1]
    return None


def extract_safe_attributes(values):
    """Extract only safe attributes from resource values."""
    safe = {}
    for attr in SAFE_ATTRIBUTES:
        if attr in values and values[attr] is not None:
            value = values[attr]
            # Sanitize tags - remove any that look sensitive
            if attr in ("tags", "tags_all") and isinstance(value, dict):
                value = {k: v for k, v in value.items() 
                        if not any(s in k.lower() for s in ["secret", "password", "key", "token", "arn"])}
            safe[attr] = value
    return safe


def parse_resources(root_module):
    """Recursively parse resources from root_module and child_modules."""
    resources = []
    
    # Parse resources in this module
    for resource in root_module.get("resources", []):
        if resource.get("mode") != "managed":
            continue
        
        res_type = resource.get("type", "")
        
        # Skip resources not in our diagram set
        if res_type not in DIAGRAM_RESOURCES:
            continue
        
        address = resource.get("address", "")
        
        resources.append({
            "address": address,
            "type": res_type,
            "name": resource.get("name", ""),
            "module": extract_module_name(address),
            "label": extract_label(resource),
            "attributes": extract_safe_attributes(resource.get("values", {}))
        })
    
    # Recursively parse child modules
    for child_module in root_module.get("child_modules", []):
        child_resources = parse_resources(child_module)
        resources.extend(child_resources)
    
    return resources


def infer_dependencies(resources):
    """Infer logical dependencies based on common architectural patterns."""
    dependencies = []
    
    # Index resources by type
    by_type = {}
    for r in resources:
        res_type = r["type"]
        if res_type not in by_type:
            by_type[res_type] = []
        by_type[res_type].append(r)
    
    # Common architectural patterns
    patterns = [
        (["aws_api_gateway_rest_api", "aws_apigatewayv2_api"], ["aws_lambda_function"]),
        (["aws_lambda_function"], ["aws_dynamodb_table"]),
        (["aws_lambda_function"], ["aws_db_instance", "aws_rds_cluster"]),
        (["aws_lambda_function"], ["aws_s3_bucket"]),
        (["aws_cloudfront_distribution"], ["aws_s3_bucket"]),
        (["aws_cloudfront_distribution"], ["aws_lb", "aws_alb"]),
        (["aws_lb", "aws_alb"], ["aws_ecs_service"]),
        (["aws_lb", "aws_alb"], ["aws_instance", "aws_autoscaling_group"]),
        (["aws_ecs_service"], ["aws_db_instance", "aws_rds_cluster"]),
        (["aws_ecs_service"], ["aws_dynamodb_table"]),
        (["aws_instance"], ["aws_db_instance", "aws_rds_cluster"]),
        (["aws_sns_topic"], ["aws_sqs_queue"]),
        (["aws_sqs_queue"], ["aws_lambda_function"]),
        (["aws_cloudwatch_event_rule", "aws_eventbridge_rule"], ["aws_lambda_function"]),
        (["aws_sfn_state_machine"], ["aws_lambda_function"]),
        (["aws_kinesis_stream"], ["aws_lambda_function"]),
        (["aws_kinesis_stream"], ["aws_kinesis_firehose_delivery_stream"]),
        (["aws_kinesis_firehose_delivery_stream"], ["aws_s3_bucket"]),
    ]
    
    seen = set()
    
    for from_types, to_types in patterns:
        for from_type in from_types:
            for to_type in to_types:
                from_resources = by_type.get(from_type, [])
                to_resources = by_type.get(to_type, [])
                
                for from_r in from_resources:
                    for to_r in to_resources:
                        # Same module or both in root
                        if from_r["module"] == to_r["module"]:
                            key = (from_r["address"], to_r["address"])
                            if key not in seen:
                                seen.add(key)
                                dependencies.append({
                                    "from": from_r["address"],
                                    "to": to_r["address"],
                                    "inferred": True
                                })
    
    return dependencies


def sanitize(data):
    """Main sanitization function."""
    # Validate input format
    if "values" not in data or "root_module" not in data.get("values", {}):
        raise ValueError(
            "Invalid input format. Expected 'terraform show -json' output.\n"
            "Make sure you ran: terraform show -json"
        )
    
    root_module = data["values"]["root_module"]
    
    # Extract resources
    resources = parse_resources(root_module)
    
    if not resources:
        all_types = set()
        def collect_types(module):
            for r in module.get("resources", []):
                all_types.add(r.get("type", "unknown"))
            for child in module.get("child_modules", []):
                collect_types(child)
        collect_types(root_module)
        
        raise ValueError(
            f"No diagram-relevant resources found.\n"
            f"Resource types in state: {sorted(all_types)}\n"
            f"Add needed types to DIAGRAM_RESOURCES in sanitizer.py"
        )
    
    # Infer dependencies
    dependencies = infer_dependencies(resources)
    
    # Extract unique modules
    modules = sorted(set(r["module"] for r in resources if r["module"]))
    
    return {
        "resources": resources,
        "dependencies": dependencies,
        "modules": modules,
        "_meta": {
            "resource_count": len(resources),
            "dependency_count": len(dependencies),
            "module_count": len(modules),
            "resource_types": sorted(set(r["type"] for r in resources))
        }
    }


def main():
    if len(sys.argv) < 3:
        print("Usage: python sanitizer.py <input.json> <output.json>")
        print("       terraform show -json | python sanitizer.py - output.json")
        sys.exit(1)
    
    input_arg = sys.argv[1]
    output_arg = sys.argv[2]
    
    # Read input
    if input_arg == "-":
        data = json.load(sys.stdin)
    else:
        input_path = Path(input_arg)
        if not input_path.exists():
            print(f"Error: {input_path} not found", file=sys.stderr)
            sys.exit(1)
        with open(input_path) as f:
            data = json.load(f)
    
    # Sanitize
    try:
        clean = sanitize(data)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Write output
    with open(output_arg, "w") as f:
        json.dump(clean, f, indent=2)
    
    # Summary
    meta = clean["_meta"]
    print(f"Sanitized: {output_arg}", file=sys.stderr)
    print(f"  Resources:    {meta['resource_count']}", file=sys.stderr)
    print(f"  Dependencies: {meta['dependency_count']} (inferred)", file=sys.stderr)
    print(f"  Modules:      {meta['module_count']}", file=sys.stderr)


if __name__ == "__main__":
    main()