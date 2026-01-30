# terraform-architecture-diagram-generator
 
# tf2diagram

Generate AWS architecture diagrams automatically from Terraform configurations.

![Example Output](crc_full.png)

## Quick Start

```bash
# Install dependencies
pip install diagrams
# macOS: brew install graphviz
# Ubuntu: apt install graphviz

# Generate diagram from Terraform plan
terraform plan -out=tfplan
terraform show -json tfplan > plan.json
python tf2diagram.py plan.json my_architecture --add-user
```

## Usage

```
python tf2diagram.py <input_json> [output_name] [--add-user]
```

| Argument | Description |
|----------|-------------|
| `input_json` | Path to Terraform JSON (from `terraform show -json`) |
| `output_name` | Output filename without extension (default: `<input>_diagram`) |
| `--add-user` | Add a "Users" entry point connecting to user-facing services |

### Recommended: Use Plan JSON (No Secrets)

```bash
terraform plan -out=tfplan
terraform show -json tfplan > plan.json
python tf2diagram.py plan.json architecture --add-user
```

### Alternative: Use State JSON (Contains Secrets)

```bash
terraform show -json > state.json
python tf2diagram.py state.json architecture --add-user
```

> ⚠️ State files contain sensitive data (ARNs, IDs, etc.). Plan JSON from `.configuration` block is preferred for documentation diagrams.

## Output

- Generates `<output_name>.png` in the current directory
- Landscape orientation (left-to-right flow)
- Auto-grouped by service tier
- Professional AWS icons

## Supported Resources

### Compute
| Terraform Resource | Diagram Icon |
|-------------------|--------------|
| `aws_instance` | EC2 |
| `aws_launch_template` | EC2 |
| `aws_autoscaling_group` | Auto Scaling |
| `aws_lambda_function` | Lambda |
| `aws_ecs_cluster` | ECS |
| `aws_ecs_service` | ECS |
| `aws_ecs_task_definition` | ECS |
| `aws_eks_cluster` | EKS |
| `aws_eks_node_group` | EKS |

### Database
| Terraform Resource | Diagram Icon |
|-------------------|--------------|
| `aws_db_instance` | RDS |
| `aws_rds_cluster` | Aurora |
| `aws_dynamodb_table` | DynamoDB |
| `aws_elasticache_cluster` | ElastiCache |
| `aws_elasticache_replication_group` | ElastiCache |

### Network
| Terraform Resource | Diagram Icon |
|-------------------|--------------|
| `aws_lb` | ALB |
| `aws_alb` | ALB |
| `aws_elb` | ELB |
| `aws_lb_target_group` | ALB |
| `aws_cloudfront_distribution` | CloudFront |
| `aws_route53_zone` | Route 53 |
| `aws_vpc` | VPC |
| `aws_api_gateway_rest_api` | API Gateway |
| `aws_apigatewayv2_api` | API Gateway |
| `aws_nat_gateway` | NAT Gateway |
| `aws_internet_gateway` | Internet Gateway |

### Storage
| Terraform Resource | Diagram Icon |
|-------------------|--------------|
| `aws_s3_bucket` | S3 |
| `aws_efs_file_system` | EFS |

### Security
| Terraform Resource | Diagram Icon |
|-------------------|--------------|
| `aws_iam_role` | IAM |
| `aws_iam_policy` | IAM |
| `aws_acm_certificate` | ACM |
| `aws_secretsmanager_secret` | Secrets Manager |
| `aws_kms_key` | KMS |

### Integration
| Terraform Resource | Diagram Icon |
|-------------------|--------------|
| `aws_sqs_queue` | SQS |
| `aws_sns_topic` | SNS |
| `aws_sfn_state_machine` | Step Functions |
| `aws_cloudwatch_event_rule` | EventBridge |

### Management
| Terraform Resource | Diagram Icon |
|-------------------|--------------|
| `aws_cloudwatch_log_group` | CloudWatch |
| `aws_cloudwatch_metric_alarm` | CloudWatch Alarm |

### Analytics
| Terraform Resource | Diagram Icon |
|-------------------|--------------|
| `aws_kinesis_stream` | Kinesis |
| `aws_athena_database` | Athena |

### ML
| Terraform Resource | Diagram Icon |
|-------------------|--------------|
| `aws_sagemaker_endpoint` | SageMaker |

## Skipped Resources

These resource types are filtered out to reduce diagram clutter:

- `aws_iam_role_policy_attachment`
- `aws_iam_policy_attachment`
- `aws_iam_instance_profile`
- `aws_security_group`
- `aws_security_group_rule`
- `aws_subnet`
- `aws_route_table`
- `aws_route_table_association`
- `aws_route`
- `aws_lb_listener`
- `aws_lb_listener_rule`
- `aws_s3_bucket_policy`
- `aws_s3_bucket_versioning`
- `aws_s3_bucket_server_side_encryption_configuration`
- `aws_s3_bucket_public_access_block`
- `aws_s3_bucket_ownership_controls`
- `aws_s3_bucket_acl`
- `aws_s3_bucket_website_configuration`
- `aws_s3_bucket_cors_configuration`
- `aws_cloudwatch_log_stream`
- `aws_lambda_permission`
- `aws_api_gateway_resource`
- `aws_api_gateway_method`
- `aws_api_gateway_integration`
- `aws_api_gateway_deployment`
- `aws_api_gateway_stage`
- `aws_route53_record`
- `aws_acm_certificate_validation`
- `aws_cloudfront_origin_access_identity`
- `aws_cloudfront_origin_access_control`
- `aws_vpc_endpoint`
- `aws_eip`
- `aws_kms_alias`

## Service Tier Grouping

Resources are automatically grouped into these tiers:

| Tier | Resource Types |
|------|----------------|
| DNS & CDN | Route 53, CloudFront |
| API | API Gateway, ALB, ELB |
| Compute | EC2, Lambda, ECS, EKS, Auto Scaling |
| Storage | S3, EFS |
| Database | RDS, Aurora, DynamoDB, ElastiCache |
| Security | ACM, IAM, Secrets Manager, KMS |
| Integration | SQS, SNS, Step Functions, EventBridge |

## Inferred Connections

The tool automatically creates connections for common patterns:

- **API Gateway → Lambda**: All API Gateway resources connect to all Lambda functions
- **User entry points**: With `--add-user`, connects Users to CloudFront, Route 53, API Gateway, and Load Balancers

## Customization

### Add New Resource Types

Edit `RESOURCE_MAP` in `tf2diagram.py`:

```python
RESOURCE_MAP = {
    # Add your resource
    "aws_new_service": SomeIcon,
    ...
}
```

### Change Output Format

Modify the `outformat` parameter in `generate_diagram()`:

```python
outformat="svg"  # or "pdf", "png"
```

### Adjust Layout

Modify `graph_attr` in `generate_diagram()`:

```python
graph_attr = {
    "splines": "spline",  # or "ortho", "polyline"
    "nodesep": "0.6",     # horizontal spacing
    "ranksep": "1.2",     # vertical spacing
    "dpi": "150"          # image resolution
}
```

## Examples

### Cloud Resume Challenge Architecture

```bash
cd cloud-resume-challenge/terraform
terraform plan -out=tfplan
terraform show -json tfplan > plan.json
python tf2diagram.py plan.json crc_architecture --add-user
```

### Multi-Module Project

```bash
cd my-terraform-project
terraform plan -out=tfplan
terraform show -json tfplan > plan.json
python tf2diagram.py plan.json infrastructure
```

Resources in Terraform modules are automatically grouped by module name.

## Troubleshooting

### "No diagrammable resources found"

The tool prints which resource types were found and their status. Check if your resources are in `RESOURCE_MAP` or `SKIP_RESOURCES`.

### Vertical layout instead of horizontal

Add `--add-user` flag. Disconnected resource groups stack vertically by default. The user entry point connects flows horizontally.

### Missing graphviz

```
# macOS
brew install graphviz

# Ubuntu/Debian
apt install graphviz

# Windows
choco install graphviz
```

## License

MIT