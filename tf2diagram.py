#!/usr/bin/env python3
"""
tf2diagram.py - Generate architecture diagrams from Terraform state/plan

Uses `terraform show -json` output directly with the diagrams library.
Supports 100+ AWS services with Graphviz layout optimizations.

Usage:
    terraform show -json | python tf2diagram.py - --title "My Architecture" --run

Requirements:
    pip install diagrams
"""

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Tuple


# =============================================================================
# COMPREHENSIVE AWS RESOURCE MAPPING (100+ services)
# Format: "terraform_type": ("diagrams.module", "ClassName", "layer", requires_vpc)
#
# Layers: edge, ingress, compute, data, storage, security, integration, analytics, ml, management
# =============================================================================

RESOURCE_MAP = {
    # =========================================================================
    # COMPUTE
    # =========================================================================
    "aws_instance": ("diagrams.aws.compute", "EC2", "compute", True),
    "aws_launch_template": ("diagrams.aws.compute", "EC2", "compute", True),
    "aws_launch_configuration": ("diagrams.aws.compute", "EC2", "compute", True),
    "aws_autoscaling_group": ("diagrams.aws.compute", "AutoScaling", "compute", True),
    "aws_spot_instance_request": ("diagrams.aws.compute", "EC2SpotInstance", "compute", True),
    "aws_ec2_fleet": ("diagrams.aws.compute", "EC2", "compute", True),
    
    # Lambda
    "aws_lambda_function": ("diagrams.aws.compute", "Lambda", "compute", False),
    "aws_lambda_function_url": ("diagrams.aws.compute", "Lambda", "ingress", False),
    "aws_lambda_layer_version": ("diagrams.aws.compute", "Lambda", "compute", False),
    
    # Containers - ECS
    "aws_ecs_cluster": ("diagrams.aws.compute", "ECS", "compute", True),
    "aws_ecs_service": ("diagrams.aws.compute", "ECS", "compute", True),
    "aws_ecs_task_definition": ("diagrams.aws.compute", "ECS", "compute", True),
    
    # Containers - EKS
    "aws_eks_cluster": ("diagrams.aws.compute", "EKS", "compute", True),
    "aws_eks_node_group": ("diagrams.aws.compute", "EKS", "compute", True),
    "aws_eks_fargate_profile": ("diagrams.aws.compute", "Fargate", "compute", True),
    
    # Containers - Other
    "aws_ecr_repository": ("diagrams.aws.compute", "ECR", "storage", False),
    "aws_lightsail_instance": ("diagrams.aws.compute", "Lightsail", "compute", False),
    "aws_batch_compute_environment": ("diagrams.aws.compute", "Batch", "compute", True),
    "aws_batch_job_definition": ("diagrams.aws.compute", "Batch", "compute", True),
    "aws_batch_job_queue": ("diagrams.aws.compute", "Batch", "compute", True),
    "aws_elastic_beanstalk_environment": ("diagrams.aws.compute", "ElasticBeanstalk", "compute", True),
    "aws_apprunner_service": ("diagrams.aws.compute", "AppRunner", "compute", False),
    
    # =========================================================================
    # DATABASE
    # =========================================================================
    # RDS
    "aws_db_instance": ("diagrams.aws.database", "RDS", "data", True),
    "aws_rds_cluster": ("diagrams.aws.database", "Aurora", "data", True),
    "aws_rds_cluster_instance": ("diagrams.aws.database", "Aurora", "data", True),
    "aws_db_proxy": ("diagrams.aws.database", "RDSProxy", "data", True),
    
    # DynamoDB
    "aws_dynamodb_table": ("diagrams.aws.database", "Dynamodb", "data", False),
    "aws_dynamodb_global_table": ("diagrams.aws.database", "DynamodbGlobalSecondaryIndex", "data", False),
    
    # ElastiCache
    "aws_elasticache_cluster": ("diagrams.aws.database", "ElasticacheForRedis", "data", True),
    "aws_elasticache_replication_group": ("diagrams.aws.database", "ElasticacheForRedis", "data", True),
    "aws_elasticache_serverless_cache": ("diagrams.aws.database", "ElasticacheForRedis", "data", False),
    
    # Other Databases
    "aws_redshift_cluster": ("diagrams.aws.database", "Redshift", "data", True),
    "aws_redshift_serverless_namespace": ("diagrams.aws.database", "Redshift", "data", False),
    "aws_neptune_cluster": ("diagrams.aws.database", "Neptune", "data", True),
    "aws_docdb_cluster": ("diagrams.aws.database", "DocumentDB", "data", True),
    "aws_keyspaces_table": ("diagrams.aws.database", "Keyspaces", "data", False),
    "aws_memorydb_cluster": ("diagrams.aws.database", "MemoryDB", "data", True),
    "aws_timestream_database": ("diagrams.aws.database", "Timestream", "data", False),
    "aws_qldb_ledger": ("diagrams.aws.database", "QLDB", "data", False),
    
    # =========================================================================
    # STORAGE
    # =========================================================================
    # S3
    "aws_s3_bucket": ("diagrams.aws.storage", "S3", "storage", False),
    "aws_s3_object": ("diagrams.aws.storage", "S3", "storage", False),
    "aws_s3_access_point": ("diagrams.aws.storage", "S3", "storage", False),
    "aws_s3control_multi_region_access_point": ("diagrams.aws.storage", "S3", "storage", False),
    
    # EFS
    "aws_efs_file_system": ("diagrams.aws.storage", "EFS", "storage", True),
    "aws_efs_access_point": ("diagrams.aws.storage", "EFS", "storage", True),
    
    # FSx
    "aws_fsx_lustre_file_system": ("diagrams.aws.storage", "Fsx", "storage", True),
    "aws_fsx_windows_file_system": ("diagrams.aws.storage", "Fsx", "storage", True),
    "aws_fsx_ontap_file_system": ("diagrams.aws.storage", "Fsx", "storage", True),
    "aws_fsx_openzfs_file_system": ("diagrams.aws.storage", "Fsx", "storage", True),
    
    # Other Storage
    "aws_backup_vault": ("diagrams.aws.storage", "Backup", "storage", False),
    "aws_backup_plan": ("diagrams.aws.storage", "Backup", "storage", False),
    "aws_storagegateway_gateway": ("diagrams.aws.storage", "StorageGateway", "storage", True),
    "aws_glacier_vault": ("diagrams.aws.storage", "S3Glacier", "storage", False),
    "aws_ebs_volume": ("diagrams.aws.storage", "EBS", "storage", True),
    "aws_ebs_snapshot": ("diagrams.aws.storage", "EBS", "storage", False),
    
    # =========================================================================
    # NETWORKING - Edge/CDN/DNS
    # =========================================================================
    "aws_cloudfront_distribution": ("diagrams.aws.network", "CloudFront", "edge", False),
    "aws_cloudfront_function": ("diagrams.aws.network", "CloudFront", "edge", False),
    "aws_route53_zone": ("diagrams.aws.network", "Route53", "edge", False),
    "aws_route53_record": ("diagrams.aws.network", "Route53", "edge", False),
    "aws_route53_health_check": ("diagrams.aws.network", "Route53", "edge", False),
    "aws_globalaccelerator_accelerator": ("diagrams.aws.network", "GlobalAccelerator", "edge", False),
    
    # =========================================================================
    # NETWORKING - Load Balancers
    # =========================================================================
    "aws_lb": ("diagrams.aws.network", "ELB", "ingress", True),
    "aws_alb": ("diagrams.aws.network", "ALB", "ingress", True),
    "aws_elb": ("diagrams.aws.network", "ELB", "ingress", True),
    "aws_lb_target_group": ("diagrams.aws.network", "ELB", "ingress", True),
    
    # =========================================================================
    # NETWORKING - API Gateway
    # =========================================================================
    "aws_api_gateway_rest_api": ("diagrams.aws.network", "APIGateway", "ingress", False),
    "aws_api_gateway_stage": ("diagrams.aws.network", "APIGateway", "ingress", False),
    "aws_apigatewayv2_api": ("diagrams.aws.network", "APIGateway", "ingress", False),
    "aws_apigatewayv2_stage": ("diagrams.aws.network", "APIGateway", "ingress", False),
    "aws_appsync_graphql_api": ("diagrams.aws.network", "Appsync", "ingress", False),
    
    # =========================================================================
    # NETWORKING - VPC Components
    # =========================================================================
    "aws_vpc": ("diagrams.aws.network", "VPC", "network", True),
    "aws_subnet": ("diagrams.aws.network", "PublicSubnet", "network", True),
    "aws_internet_gateway": ("diagrams.aws.network", "InternetGateway", "network", True),
    "aws_nat_gateway": ("diagrams.aws.network", "NATGateway", "network", True),
    "aws_vpn_gateway": ("diagrams.aws.network", "VPNGateway", "network", True),
    "aws_customer_gateway": ("diagrams.aws.network", "VPNGateway", "network", True),
    "aws_vpc_peering_connection": ("diagrams.aws.network", "VPCPeering", "network", True),
    "aws_transit_gateway": ("diagrams.aws.network", "TransitGateway", "network", False),
    "aws_vpc_endpoint": ("diagrams.aws.network", "Endpoint", "network", True),
    "aws_ec2_transit_gateway": ("diagrams.aws.network", "TransitGateway", "network", False),
    "aws_dx_connection": ("diagrams.aws.network", "DirectConnect", "network", False),
    "aws_vpn_connection": ("diagrams.aws.network", "SiteToSiteVpn", "network", True),
    "aws_network_interface": ("diagrams.aws.network", "ENI", "network", True),
    "aws_eip": ("diagrams.aws.network", "ElasticIP", "network", True),
    
    # =========================================================================
    # SECURITY
    # =========================================================================
    # WAF & Shield
    "aws_wafv2_web_acl": ("diagrams.aws.security", "WAF", "edge", False),
    "aws_waf_web_acl": ("diagrams.aws.security", "WAF", "edge", False),
    "aws_shield_protection": ("diagrams.aws.security", "Shield", "edge", False),
    
    # IAM
    "aws_iam_role": ("diagrams.aws.security", "IAM", "security", False),
    "aws_iam_user": ("diagrams.aws.security", "IAM", "security", False),
    "aws_iam_group": ("diagrams.aws.security", "IAM", "security", False),
    "aws_iam_policy": ("diagrams.aws.security", "IAMPermissions", "security", False),
    
    # Cognito
    "aws_cognito_user_pool": ("diagrams.aws.security", "Cognito", "security", False),
    "aws_cognito_identity_pool": ("diagrams.aws.security", "Cognito", "security", False),
    
    # Secrets & Keys
    "aws_secretsmanager_secret": ("diagrams.aws.security", "SecretsManager", "security", False),
    "aws_kms_key": ("diagrams.aws.security", "KMS", "security", False),
    "aws_kms_alias": ("diagrams.aws.security", "KMS", "security", False),
    "aws_acm_certificate": ("diagrams.aws.security", "ACM", "security", False),
    "aws_acmpca_certificate_authority": ("diagrams.aws.security", "ACM", "security", False),
    
    # Security Services
    "aws_guardduty_detector": ("diagrams.aws.security", "Guardduty", "security", False),
    "aws_inspector_assessment_template": ("diagrams.aws.security", "Inspector", "security", False),
    "aws_macie2_account": ("diagrams.aws.security", "Macie", "security", False),
    "aws_securityhub_account": ("diagrams.aws.security", "SecurityHub", "security", False),
    "aws_detective_graph": ("diagrams.aws.security", "Detective", "security", False),
    
    # Firewall
    "aws_networkfirewall_firewall": ("diagrams.aws.security", "NetworkFirewall", "security", True),
    "aws_security_group": ("diagrams.aws.security", "SecurityGroup", "security", True),
    
    # =========================================================================
    # INTEGRATION / MESSAGING
    # =========================================================================
    # Queues & Topics
    "aws_sqs_queue": ("diagrams.aws.integration", "SQS", "integration", False),
    "aws_sns_topic": ("diagrams.aws.integration", "SNS", "integration", False),
    "aws_mq_broker": ("diagrams.aws.integration", "MQ", "integration", True),
    
    # EventBridge
    "aws_cloudwatch_event_rule": ("diagrams.aws.integration", "Eventbridge", "integration", False),
    "aws_cloudwatch_event_bus": ("diagrams.aws.integration", "Eventbridge", "integration", False),
    "aws_schemas_registry": ("diagrams.aws.integration", "Eventbridge", "integration", False),
    
    # Step Functions
    "aws_sfn_state_machine": ("diagrams.aws.integration", "StepFunctions", "integration", False),
    "aws_sfn_activity": ("diagrams.aws.integration", "StepFunctions", "integration", False),
    
    # Other Integration
    "aws_pipes_pipe": ("diagrams.aws.integration", "EventbridgePipes", "integration", False),
    "aws_scheduler_schedule": ("diagrams.aws.integration", "EventbridgeScheduler", "integration", False),
    
    # =========================================================================
    # ANALYTICS
    # =========================================================================
    # Kinesis
    "aws_kinesis_stream": ("diagrams.aws.analytics", "KinesisDataStreams", "analytics", False),
    "aws_kinesis_firehose_delivery_stream": ("diagrams.aws.analytics", "KinesisDataFirehose", "analytics", False),
    "aws_kinesis_analytics_application": ("diagrams.aws.analytics", "KinesisDataAnalytics", "analytics", False),
    "aws_kinesisanalyticsv2_application": ("diagrams.aws.analytics", "KinesisDataAnalytics", "analytics", False),
    
    # Glue
    "aws_glue_catalog_database": ("diagrams.aws.analytics", "GlueDataCatalog", "analytics", False),
    "aws_glue_crawler": ("diagrams.aws.analytics", "Glue", "analytics", False),
    "aws_glue_job": ("diagrams.aws.analytics", "Glue", "analytics", False),
    "aws_glue_trigger": ("diagrams.aws.analytics", "Glue", "analytics", False),
    
    # Athena & EMR
    "aws_athena_workgroup": ("diagrams.aws.analytics", "Athena", "analytics", False),
    "aws_athena_database": ("diagrams.aws.analytics", "Athena", "analytics", False),
    "aws_emr_cluster": ("diagrams.aws.analytics", "EMR", "analytics", True),
    "aws_emrserverless_application": ("diagrams.aws.analytics", "EMR", "analytics", False),
    
    # OpenSearch
    "aws_opensearch_domain": ("diagrams.aws.analytics", "Elasticsearch", "analytics", True),
    "aws_elasticsearch_domain": ("diagrams.aws.analytics", "Elasticsearch", "analytics", True),
    
    # Lake Formation & Data Exchange
    "aws_lakeformation_resource": ("diagrams.aws.analytics", "LakeFormation", "analytics", False),
    "aws_dataexchange_data_set": ("diagrams.aws.analytics", "DataExchange", "analytics", False),
    
    # QuickSight
    "aws_quicksight_data_source": ("diagrams.aws.analytics", "Quicksight", "analytics", False),
    "aws_quicksight_analysis": ("diagrams.aws.analytics", "Quicksight", "analytics", False),
    
    # MSK (Kafka)
    "aws_msk_cluster": ("diagrams.aws.analytics", "ManagedStreamingForKafka", "analytics", True),
    "aws_msk_serverless_cluster": ("diagrams.aws.analytics", "ManagedStreamingForKafka", "analytics", False),
    
    # =========================================================================
    # MACHINE LEARNING
    # =========================================================================
    "aws_sagemaker_endpoint": ("diagrams.aws.ml", "Sagemaker", "ml", True),
    "aws_sagemaker_model": ("diagrams.aws.ml", "Sagemaker", "ml", False),
    "aws_sagemaker_notebook_instance": ("diagrams.aws.ml", "SagemakerNotebook", "ml", True),
    "aws_sagemaker_domain": ("diagrams.aws.ml", "Sagemaker", "ml", True),
    "aws_sagemaker_feature_group": ("diagrams.aws.ml", "Sagemaker", "ml", False),
    "aws_bedrock_custom_model": ("diagrams.aws.ml", "Bedrock", "ml", False),
    "aws_comprehend_entity_recognizer": ("diagrams.aws.ml", "Comprehend", "ml", False),
    "aws_lex_bot": ("diagrams.aws.ml", "Lex", "ml", False),
    "aws_polly_lexicon": ("diagrams.aws.ml", "Polly", "ml", False),
    "aws_rekognition_collection": ("diagrams.aws.ml", "Rekognition", "ml", False),
    "aws_textract_document_analyzer": ("diagrams.aws.ml", "Textract", "ml", False),
    "aws_transcribe_vocabulary": ("diagrams.aws.ml", "Transcribe", "ml", False),
    "aws_translate_terminology": ("diagrams.aws.ml", "Translate", "ml", False),
    "aws_personalize_dataset_group": ("diagrams.aws.ml", "Personalize", "ml", False),
    "aws_forecast_dataset_group": ("diagrams.aws.ml", "Forecast", "ml", False),
    "aws_kendra_index": ("diagrams.aws.ml", "Kendra", "ml", False),
    
    # =========================================================================
    # MANAGEMENT & MONITORING
    # =========================================================================
    # CloudWatch
    "aws_cloudwatch_log_group": ("diagrams.aws.management", "Cloudwatch", "management", False),
    "aws_cloudwatch_metric_alarm": ("diagrams.aws.management", "CloudwatchAlarm", "management", False),
    "aws_cloudwatch_dashboard": ("diagrams.aws.management", "Cloudwatch", "management", False),
    "aws_cloudwatch_log_subscription_filter": ("diagrams.aws.management", "Cloudwatch", "management", False),
    
    # X-Ray & Observability
    "aws_xray_sampling_rule": ("diagrams.aws.management", "Xray", "management", False),
    "aws_oam_sink": ("diagrams.aws.management", "Cloudwatch", "management", False),
    
    # Systems Manager
    "aws_ssm_parameter": ("diagrams.aws.management", "SystemsManager", "management", False),
    "aws_ssm_document": ("diagrams.aws.management", "SystemsManager", "management", False),
    "aws_ssm_maintenance_window": ("diagrams.aws.management", "SystemsManager", "management", False),
    "aws_ssm_patch_baseline": ("diagrams.aws.management", "SystemsManager", "management", False),
    
    # Config & CloudTrail
    "aws_config_config_rule": ("diagrams.aws.management", "Config", "management", False),
    "aws_config_configuration_recorder": ("diagrams.aws.management", "Config", "management", False),
    "aws_cloudtrail": ("diagrams.aws.management", "Cloudtrail", "management", False),
    
    # Organizations & Control Tower
    "aws_organizations_account": ("diagrams.aws.management", "Organizations", "management", False),
    "aws_organizations_organizational_unit": ("diagrams.aws.management", "Organizations", "management", False),
    "aws_controltower_control": ("diagrams.aws.management", "ControlTower", "management", False),
    
    # Other Management
    "aws_servicecatalog_portfolio": ("diagrams.aws.management", "ServiceCatalog", "management", False),
    "aws_resourcegroups_group": ("diagrams.aws.management", "ResourceGroups", "management", False),
    "aws_health_event": ("diagrams.aws.management", "Health", "management", False),
    
    # =========================================================================
    # DEVELOPER TOOLS
    # =========================================================================
    "aws_codecommit_repository": ("diagrams.aws.devtools", "Codecommit", "devtools", False),
    "aws_codebuild_project": ("diagrams.aws.devtools", "Codebuild", "devtools", False),
    "aws_codedeploy_app": ("diagrams.aws.devtools", "Codedeploy", "devtools", False),
    "aws_codepipeline": ("diagrams.aws.devtools", "Codepipeline", "devtools", False),
    "aws_codeartifact_repository": ("diagrams.aws.devtools", "Codeartifact", "devtools", False),
    "aws_codestarconnections_connection": ("diagrams.aws.devtools", "Codestar", "devtools", False),
    "aws_cloud9_environment_ec2": ("diagrams.aws.devtools", "Cloud9", "devtools", True),
    
    # =========================================================================
    # APPLICATION SERVICES
    # =========================================================================
    "aws_ses_domain_identity": ("diagrams.aws.engagement", "SES", "application", False),
    "aws_ses_email_identity": ("diagrams.aws.engagement", "SES", "application", False),
    "aws_pinpoint_app": ("diagrams.aws.engagement", "Pinpoint", "application", False),
    "aws_connect_instance": ("diagrams.aws.engagement", "Connect", "application", False),
    
    # =========================================================================
    # IOT
    # =========================================================================
    "aws_iot_thing": ("diagrams.aws.iot", "IotCore", "iot", False),
    "aws_iot_topic_rule": ("diagrams.aws.iot", "IotRule", "iot", False),
    "aws_iot_certificate": ("diagrams.aws.iot", "IotCertificate", "iot", False),
    "aws_iot_policy": ("diagrams.aws.iot", "IotPolicy", "iot", False),
    "aws_iotevents_detector_model": ("diagrams.aws.iot", "IotEvents", "iot", False),
    "aws_iot_analytics_channel": ("diagrams.aws.iot", "IotAnalytics", "iot", False),
    "aws_greengrass_group": ("diagrams.aws.iot", "IotGreengrass", "iot", False),
    
    # =========================================================================
    # MEDIA SERVICES
    # =========================================================================
    "aws_media_convert_queue": ("diagrams.aws.media", "MediaConvert", "media", False),
    "aws_media_live_channel": ("diagrams.aws.media", "MediaLive", "media", False),
    "aws_media_package_channel": ("diagrams.aws.media", "MediaPackage", "media", False),
    "aws_media_store_container": ("diagrams.aws.media", "MediaStore", "media", False),
    "aws_ivs_channel": ("diagrams.aws.media", "InteractiveVideoService", "media", False),
    
    # =========================================================================
    # COST MANAGEMENT
    # =========================================================================
    "aws_budgets_budget": ("diagrams.aws.cost", "Budgets", "cost", False),
    "aws_ce_cost_category": ("diagrams.aws.cost", "CostExplorer", "cost", False),
    "aws_cur_report_definition": ("diagrams.aws.cost", "CostAndUsageReport", "cost", False),
}

# Layers for connection inference (flow order)
LAYER_FLOW = ["edge", "ingress", "compute", "integration", "analytics", "ml", "data", "storage"]


# =============================================================================
# GRAPHVIZ LAYOUT ATTRIBUTES
# =============================================================================

DIAGRAM_ATTRS = {
    "splines": "ortho",        # Orthogonal arrows (no diagonals)
    "nodesep": "0.8",          # Horizontal spacing between nodes
    "ranksep": "1.0",          # Vertical spacing between ranks
    "compound": "true",        # Allow edges between clusters
    "concentrate": "true",     # Merge parallel edges
}

CLUSTER_ATTRS = {
    "style": "rounded",
    "bgcolor": "#f5f5f5",
    "pencolor": "#cccccc",
}


def parse_terraform_json(data: dict) -> Dict[str, dict]:
    """Parse terraform show -json output."""
    resources = {}
    
    # Handle state, plan, or direct resource list formats
    if "values" in data:
        root = data["values"].get("root_module", {})
    elif "planned_values" in data:
        root = data["planned_values"].get("root_module", {})
    elif "resources" in data:
        root = data
    else:
        print("Error: Unrecognized terraform JSON format", file=sys.stderr)
        return {}
    
    def process_module(module, prefix=""):
        for res in module.get("resources", []):
            res_type = res.get("type", "")
            res_name = res.get("name", "")
            res_values = res.get("values", {})
            
            if res_type not in RESOURCE_MAP:
                continue
            
            full_name = f"{prefix}{res_name}" if prefix else res_name
            res_id = f"{res_type}.{full_name}"
            mapping = RESOURCE_MAP[res_type]
            
            resources[res_id] = {
                "type": res_type,
                "name": full_name,
                "values": res_values,
                "module": mapping[0],
                "class": mapping[1],
                "layer": mapping[2],
                "requires_vpc": mapping[3],
            }
        
        # Process child modules
        for child in module.get("child_modules", []):
            child_addr = child.get("address", "")
            child_prefix = child_addr.split(".")[-1] + "_" if child_addr else ""
            process_module(child, child_prefix)
    
    process_module(root)
    return resources


def infer_connections(resources: dict) -> List[Tuple[str, str]]:
    """Infer connections based on layer flow and resource types."""
    connections = []
    seen = set()
    
    def add(src, tgt):
        if src != tgt and src in resources and tgt in resources:
            if (src, tgt) not in seen:
                seen.add((src, tgt))
                connections.append((src, tgt))
    
    # Group by layer
    by_layer = defaultdict(list)
    for rid, res in resources.items():
        by_layer[res["layer"]].append(rid)
    
    # Connect layers in flow order
    for i, layer in enumerate(LAYER_FLOW[:-1]):
        next_layers = LAYER_FLOW[i+1:]
        for src in by_layer[layer]:
            # Connect to next available layer
            for next_layer in next_layers:
                if by_layer[next_layer]:
                    for tgt in by_layer[next_layer]:
                        add(src, tgt)
                    break  # Only connect to immediate next layer with resources
    
    # Special patterns
    # CloudFront -> S3 (static content)
    for rid in by_layer["edge"]:
        if "cloudfront" in rid.lower():
            for storage in by_layer["storage"]:
                if "s3" in storage.lower():
                    add(rid, storage)
    
    # Lambda -> DynamoDB (serverless pattern)
    for compute in by_layer["compute"]:
        if "lambda" in compute.lower():
            for data in by_layer["data"]:
                if "dynamodb" in data.lower():
                    add(compute, data)
    
    return connections


def generate_diagram_code(
    resources: dict,
    connections: List[Tuple[str, str]],
    title: str,
    fmt: str,
    direction: str = "LR"
) -> str:
    """Generate Python code for diagrams library with layout optimizations."""
    
    # Collect imports
    imports = {"from diagrams import Diagram, Cluster, Edge"}
    for res in resources.values():
        imports.add(f"from {res['module']} import {res['class']}")
    
    # Check for VPC resources
    has_vpc = any(res["requires_vpc"] for res in resources.values())
    
    def var(res_id):
        return res_id.replace(".", "_").replace("-", "_")
    
    # Sort by layer for logical grouping
    def sort_key(rid):
        res = resources[rid]
        layer_idx = LAYER_FLOW.index(res["layer"]) if res["layer"] in LAYER_FLOW else 99
        return (layer_idx, res["name"])
    
    sorted_res = sorted(resources.keys(), key=sort_key)
    
    # Build graph attributes string
    graph_attrs = ", ".join(f'"{k}": "{v}"' for k, v in DIAGRAM_ATTRS.items())
    
    lines = [
        "#!/usr/bin/env python3",
        '"""Generated by tf2diagram.py"""',
        "",
        *sorted(imports),
        "",
        f'graph_attr = {{{graph_attrs}}}',
        "",
        f'with Diagram("{title}", show=False, direction="{direction}", outformat="{fmt}", graph_attr=graph_attr):',
    ]
    
    if has_vpc:
        vpc_res = [r for r in sorted_res if resources[r]["requires_vpc"]]
        non_vpc = [r for r in sorted_res if not resources[r]["requires_vpc"]]
        
        # Non-VPC resources (edge/serverless)
        if non_vpc:
            lines.append("")
            lines.append("    # External / Serverless Services")
            for rid in non_vpc:
                res = resources[rid]
                lines.append(f'    {var(rid)} = {res["class"]}("{res["name"]}")')
        
        # VPC resources
        if vpc_res:
            lines.append("")
            lines.append('    with Cluster("VPC"):')
            
            # Group by subnet type if detectable, otherwise just list
            public_types = {"aws_lb", "aws_alb", "aws_elb", "aws_nat_gateway"}
            private_types = {"aws_db_instance", "aws_rds_cluster", "aws_elasticache_cluster"}
            
            public = [r for r in vpc_res if resources[r]["type"] in public_types]
            private = [r for r in vpc_res if resources[r]["type"] in private_types]
            other = [r for r in vpc_res if r not in public and r not in private]
            
            if public:
                lines.append('        with Cluster("Public Subnet"):')
                for rid in public:
                    res = resources[rid]
                    lines.append(f'            {var(rid)} = {res["class"]}("{res["name"]}")')
            
            if private:
                lines.append('        with Cluster("Private Subnet"):')
                for rid in private:
                    res = resources[rid]
                    lines.append(f'            {var(rid)} = {res["class"]}("{res["name"]}")')
            
            if other:
                for rid in other:
                    res = resources[rid]
                    lines.append(f'        {var(rid)} = {res["class"]}("{res["name"]}")')
    else:
        # Pure serverless - group by layer
        lines.append("")
        current_layer = None
        for rid in sorted_res:
            res = resources[rid]
            if res["layer"] != current_layer:
                current_layer = res["layer"]
                lines.append(f"    # {current_layer.title()}")
            lines.append(f'    {var(rid)} = {res["class"]}("{res["name"]}")')
    
    # Connections
    if connections:
        lines.append("")
        lines.append("    # Connections")
        for src, tgt in connections:
            lines.append(f'    {var(src)} >> {var(tgt)}')
    
    lines.append("")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Generate diagram from terraform show -json',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
    terraform show -json | python tf2diagram.py - --title "My App" --run
    terraform show -json > state.json && python tf2diagram.py state.json -o arch.py --run
    terraform plan -out=plan.tfplan && terraform show -json plan.tfplan | python tf2diagram.py -
        '''
    )
    parser.add_argument('input', help='JSON file or - for stdin')
    parser.add_argument('--title', default='Architecture', help='Diagram title')
    parser.add_argument('--format', choices=['png', 'svg', 'pdf', 'dot'], default='svg')
    parser.add_argument('--direction', choices=['LR', 'TB', 'RL', 'BT'], default='LR',
                        help='Layout direction: LR (left-right), TB (top-bottom)')
    parser.add_argument('-o', '--output', help='Output Python file (default: stdout)')
    parser.add_argument('--run', action='store_true', help='Generate diagram immediately')
    
    args = parser.parse_args()
    
    # Read JSON
    if args.input == '-':
        data = json.load(sys.stdin)
    else:
        with open(args.input) as f:
            data = json.load(f)
    
    resources = parse_terraform_json(data)
    
    if not resources:
        print("No supported resources found", file=sys.stderr)
        print(f"Supported types: {len(RESOURCE_MAP)}", file=sys.stderr)
        sys.exit(1)
    
    print(f"Found {len(resources)} resources", file=sys.stderr)
    for layer in LAYER_FLOW:
        count = sum(1 for r in resources.values() if r["layer"] == layer)
        if count:
            print(f"  {layer}: {count}", file=sys.stderr)
    
    connections = infer_connections(resources)
    print(f"Inferred {len(connections)} connections", file=sys.stderr)
    
    code = generate_diagram_code(resources, connections, args.title, args.format, args.direction)
    
    if args.output:
        Path(args.output).write_text(code)
        print(f"Wrote {args.output}", file=sys.stderr)
        if args.run:
            import subprocess
            subprocess.run([sys.executable, args.output])
    elif args.run:
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            import subprocess
            subprocess.run([sys.executable, f.name])
            print(f"Generated: {args.title.lower().replace(' ', '_')}.{args.format}", file=sys.stderr)
    else:
        print(code)


if __name__ == "__main__":
    main()