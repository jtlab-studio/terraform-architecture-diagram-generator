#!/usr/bin/env python3
"""
files2svg.py - Generate AWS architecture diagrams from Terraform .tf files

Parses HCL directly to understand:
- VPC and subnet topology (public vs private)
- Security group relationships (who can talk to whom)
- Resource placement (which subnet each resource is in)

Usage:
    python files2svg.py ./terraform/ output.svg --title "My Architecture"

Requirements:
    pip install python-hcl2
"""

import argparse
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

try:
    import hcl2
except ImportError:
    print("Error: python-hcl2 is required. Install with:", file=sys.stderr)
    print("  pip install python-hcl2", file=sys.stderr)
    sys.exit(1)

# =============================================================================
# CONFIGURATION
# =============================================================================

# Visual constants
GRID = 8
NODE_W = 112
NODE_H = 104
H_GAP = 48
V_GAP = 24
MODULE_PAD = 24
MODULE_HDR = 32
CANVAS_PAD = 64
USER_W = 80
ARROW_GAP = 8

COLORS = {
    "bg": "#ffffff",
    "module_bg": "#f8f9fa",
    "module_border": "#e9ecef",
    "module_header": "#232f3e",
    "node_bg": "#ffffff",
    "node_border": "#d5dbdb",
    "text": "#232f3e",
    "text_secondary": "#545b64",
    "arrow": "#545b64",
    "user": "#232f3e",
    "public_subnet": "#e8f5e9",  # Light green for public
    "private_subnet": "#fff3e0",  # Light orange for private
}

# Resource categories for icon colors
CATEGORY_COLORS = {
    "compute": "#ED7100",      # Orange - EC2, Lambda, ECS
    "database": "#C925D1",     # Purple - RDS, DynamoDB
    "storage": "#7AA116",      # Green - S3, EFS
    "network": "#8C4FFF",      # Purple - VPC, ALB, CloudFront
    "security": "#DD344C",     # Red - WAF, ACM, IAM
    "integration": "#E7157B",  # Pink - API Gateway, SQS, SNS
}

# Resource type metadata: (display_name, short_label, category, is_public)
RESOURCE_INFO = {
    # Compute
    "aws_instance": ("EC2", "EC2", "compute", True),
    "aws_launch_template": ("Launch Template", "LT", "compute", False),
    "aws_autoscaling_group": ("Auto Scaling", "ASG", "compute", True),
    "aws_lambda_function": ("Lambda", "λ", "compute", False),
    "aws_ecs_cluster": ("ECS Cluster", "ECS", "compute", False),
    "aws_ecs_service": ("ECS Service", "ECS", "compute", True),
    "aws_ecs_task_definition": ("Task Def", "Task", "compute", False),
    "aws_eks_cluster": ("EKS", "EKS", "compute", False),
    
    # Database
    "aws_db_instance": ("RDS", "RDS", "database", False),
    "aws_rds_cluster": ("Aurora", "Aurora", "database", False),
    "aws_dynamodb_table": ("DynamoDB", "DDB", "database", False),
    "aws_elasticache_cluster": ("ElastiCache", "Cache", "database", False),
    "aws_elasticache_replication_group": ("ElastiCache", "Cache", "database", False),
    
    # Storage
    "aws_s3_bucket": ("S3", "S3", "storage", True),
    "aws_efs_file_system": ("EFS", "EFS", "storage", False),
    
    # Network - Load Balancers
    "aws_lb": ("Load Balancer", "ALB", "network", True),
    "aws_alb": ("Load Balancer", "ALB", "network", True),
    "aws_elb": ("Classic LB", "ELB", "network", True),
    
    # Network - CDN/DNS
    "aws_cloudfront_distribution": ("CloudFront", "CF", "network", True),
    "aws_route53_zone": ("Route 53", "R53", "network", True),
    "aws_route53_record": ("DNS Record", "DNS", "network", True),
    
    # Network - VPC (usually skip these but track for topology)
    "aws_vpc": ("VPC", "VPC", "network", False),
    "aws_subnet": ("Subnet", "Subnet", "network", False),
    "aws_internet_gateway": ("Internet GW", "IGW", "network", True),
    "aws_nat_gateway": ("NAT Gateway", "NAT", "network", True),
    
    # Security
    "aws_security_group": ("Security Group", "SG", "security", False),
    "aws_wafv2_web_acl": ("WAF", "WAF", "security", True),
    "aws_acm_certificate": ("ACM Cert", "ACM", "security", False),
    
    # Integration
    "aws_api_gateway_rest_api": ("API Gateway", "API", "integration", True),
    "aws_apigatewayv2_api": ("API Gateway", "API", "integration", True),
    "aws_sqs_queue": ("SQS", "SQS", "integration", False),
    "aws_sns_topic": ("SNS", "SNS", "integration", False),
    "aws_lambda_function_url": ("Lambda URL", "URL", "integration", True),
}

# Resources to skip in diagrams (infrastructure plumbing and configuration resources)
SKIP_RESOURCES = {
    # VPC infrastructure
    "aws_vpc", "aws_subnet", "aws_internet_gateway", "aws_nat_gateway",
    "aws_route_table", "aws_route_table_association", "aws_route",
    "aws_security_group", "aws_security_group_rule",
    "aws_eip", "aws_network_interface",
    
    # IAM
    "aws_iam_role", "aws_iam_policy", "aws_iam_role_policy_attachment",
    "aws_iam_role_policy", "aws_iam_policy_document", "aws_iam_instance_profile",
    
    # Subnet groups
    "aws_db_subnet_group", "aws_elasticache_subnet_group",
    
    # Load balancer configuration
    "aws_lb_target_group", "aws_lb_listener", "aws_lb_target_group_attachment",
    "aws_lb_listener_rule", "aws_lb_listener_certificate",
    
    # CloudWatch
    "aws_cloudwatch_log_group", "aws_cloudwatch_metric_alarm",
    "aws_cloudwatch_log_subscription_filter",
    
    # Secrets/Config
    "aws_kms_key", "aws_kms_alias",
    "aws_ssm_parameter", "aws_secretsmanager_secret", "aws_secretsmanager_secret_version",
    
    # S3 configuration resources (keep only aws_s3_bucket)
    "aws_s3_bucket_policy", "aws_s3_bucket_versioning", 
    "aws_s3_bucket_website_configuration", "aws_s3_bucket_cors_configuration",
    "aws_s3_bucket_public_access_block", "aws_s3_bucket_server_side_encryption_configuration",
    "aws_s3_bucket_lifecycle_configuration", "aws_s3_bucket_notification",
    "aws_s3_bucket_acl", "aws_s3_bucket_ownership_controls",
    "aws_s3_object",
    
    # CloudFront configuration
    "aws_cloudfront_origin_access_control", "aws_cloudfront_origin_access_identity",
    "aws_cloudfront_cache_policy", "aws_cloudfront_response_headers_policy",
    
    # ACM
    "aws_acm_certificate", "aws_acm_certificate_validation",
    "aws_route53_record",  # Usually DNS validation records, skip by default
    
    # Lambda configuration
    "aws_lambda_permission", "aws_lambda_event_source_mapping",
    
    # API Gateway configuration
    "aws_api_gateway_resource", "aws_api_gateway_method", "aws_api_gateway_integration",
    "aws_api_gateway_deployment", "aws_api_gateway_stage",
    "aws_apigatewayv2_stage", "aws_apigatewayv2_integration", "aws_apigatewayv2_route",
    
    # WAF configuration
    "aws_wafv2_web_acl_association",
}

# Resources that REQUIRE VPC (if none of these exist, don't show VPC)
VPC_RESOURCES = {
    "aws_instance", "aws_lb", "aws_alb", "aws_elb",
    "aws_db_instance", "aws_rds_cluster",
    "aws_elasticache_cluster", "aws_elasticache_replication_group",
    "aws_ecs_service", "aws_eks_cluster",
    "aws_nat_gateway", "aws_efs_file_system",
}

# Serverless/managed resources (no VPC needed)
SERVERLESS_RESOURCES = {
    "aws_lambda_function", "aws_lambda_function_url",
    "aws_dynamodb_table",
    "aws_s3_bucket",
    "aws_cloudfront_distribution",
    "aws_api_gateway_rest_api", "aws_apigatewayv2_api",
    "aws_sqs_queue", "aws_sns_topic",
    "aws_route53_zone",
    "aws_wafv2_web_acl",
}

# Resources that indicate public tier placement (only for VPC architectures)
PUBLIC_INDICATORS = {
    "aws_lb", "aws_alb", "aws_elb", 
    "aws_instance",  # EC2 can be public or private, default to public
}

# Resources that indicate private tier placement (only for VPC architectures)
PRIVATE_INDICATORS = {
    "aws_db_instance", "aws_rds_cluster",
    "aws_elasticache_cluster", "aws_elasticache_replication_group",
    "aws_efs_file_system",
}


# =============================================================================
# DATA STRUCTURES
# =============================================================================

@dataclass
class Resource:
    """Represents a Terraform resource."""
    id: str                           # e.g., "aws_instance.web"
    resource_type: str                # e.g., "aws_instance"
    name: str                         # e.g., "web"
    attributes: Dict                  # All HCL attributes
    
    # Derived placement info
    tier: str = "unknown"             # "public", "private", "unknown"
    vpc_ref: Optional[str] = None     # Reference to VPC
    subnet_ref: Optional[str] = None  # Reference to subnet
    security_groups: List[str] = field(default_factory=list)
    
    # For display
    display_name: str = ""
    short_label: str = ""
    category: str = "compute"


@dataclass
class Connection:
    """Represents a connection between resources."""
    from_id: str
    to_id: str
    connection_type: str  # "security_group", "subnet", "explicit", "implicit"


@dataclass 
class Position:
    x: int
    y: int
    w: int = NODE_W
    h: int = NODE_H
    
    @property
    def cx(self) -> int: return self.x + self.w // 2
    @property
    def cy(self) -> int: return self.y + self.h // 2
    @property
    def right(self) -> int: return self.x + self.w
    @property
    def left(self) -> int: return self.x


# =============================================================================
# HCL PARSER
# =============================================================================

def parse_tf_files(tf_dir: Path) -> Tuple[Dict[str, Resource], Dict[str, dict], Dict[str, dict]]:
    """
    Parse all .tf files in directory.
    
    Returns:
        resources: Dict of resource_id -> Resource
        security_groups: Dict of sg_id -> {ingress, egress rules}
        subnets: Dict of subnet_id -> {cidr, public/private, vpc}
    """
    resources = {}
    security_groups = {}
    subnets = {}
    
    tf_files = list(tf_dir.rglob("*.tf"))
    if not tf_files:
        print(f"Warning: No .tf files found in {tf_dir}", file=sys.stderr)
        return resources, security_groups, subnets
    
    for tf_file in tf_files:
        try:
            with open(tf_file, 'r') as f:
                parsed = hcl2.load(f)
        except Exception as e:
            print(f"Warning: Could not parse {tf_file}: {e}", file=sys.stderr)
            continue
        
        # Process resources
        for resource_block in parsed.get("resource", []):
            for resource_type, instances in resource_block.items():
                # instances is {name: attrs} dict
                if isinstance(instances, dict):
                    for name, attrs in instances.items():
                        if not isinstance(attrs, dict):
                            continue
                        
                        resource_id = f"{resource_type}.{name}"
                        
                        # Create resource object
                        info = RESOURCE_INFO.get(resource_type, (resource_type, resource_type[:3].upper(), "compute", False))
                        resource = Resource(
                            id=resource_id,
                            resource_type=resource_type,
                            name=name,
                            attributes=attrs,
                            display_name=info[0],
                            short_label=info[1],
                            category=info[2],
                        )
                        
                        # Extract placement info
                        resource.subnet_ref = extract_ref(attrs.get("subnet_id"))
                        resource.vpc_ref = extract_ref(attrs.get("vpc_id"))
                        
                        # Security groups
                        sg_ids = attrs.get("vpc_security_group_ids", attrs.get("security_groups", []))
                        if isinstance(sg_ids, list):
                            resource.security_groups = [extract_ref(sg) for sg in sg_ids if extract_ref(sg)]
                        
                        # Determine tier based on resource type
                        if resource_type in PUBLIC_INDICATORS:
                            resource.tier = "public"
                        elif resource_type in PRIVATE_INDICATORS:
                            resource.tier = "private"
                        else:
                            # Check if subnet name hints at public/private
                            subnet_ref = resource.subnet_ref or ""
                            if "public" in subnet_ref.lower():
                                resource.tier = "public"
                            elif "private" in subnet_ref.lower():
                                resource.tier = "private"
                        
                        resources[resource_id] = resource
                        
                        # Track security groups
                        if resource_type == "aws_security_group":
                            security_groups[resource_id] = {
                                "ingress": attrs.get("ingress", []),
                                "egress": attrs.get("egress", []),
                                "name": attrs.get("name", name),
                            }
                        
                        # Track subnets
                        if resource_type == "aws_subnet":
                            is_public = attrs.get("map_public_ip_on_launch", False)
                            if not is_public:
                                # Check name for hints
                                subnet_name = attrs.get("tags", {}).get("Name", name)
                                is_public = "public" in str(subnet_name).lower()
                            
                            subnets[resource_id] = {
                                "cidr": attrs.get("cidr_block"),
                                "public": is_public,
                                "vpc_ref": extract_ref(attrs.get("vpc_id")),
                                "name": name,
                            }
    
    return resources, security_groups, subnets


def extract_ref(value) -> Optional[str]:
    """Extract resource reference from HCL value."""
    if value is None:
        return None
    
    if isinstance(value, str):
        # Handle "${aws_subnet.public.id}" format
        match = re.search(r'\$\{([^}]+)\}', value)
        if match:
            ref = match.group(1)
            # Remove .id, .arn suffixes
            ref = re.sub(r'\.(id|arn|name)$', '', ref)
            return ref
        
        # Handle "aws_subnet.public.id" format (HCL2)
        if value.startswith("aws_"):
            ref = re.sub(r'\.(id|arn|name)$', '', value)
            return ref
    
    elif isinstance(value, list) and len(value) == 1:
        return extract_ref(value[0])
    
    return None


# =============================================================================
# CONNECTION INFERENCE
# =============================================================================

def infer_connections(
    resources: Dict[str, Resource],
    security_groups: Dict[str, dict]
) -> List[Connection]:
    """
    Infer connections between resources based on:
    1. Security group rules (who can talk to whom)
    2. Explicit references in attributes
    3. Architectural patterns (ALB → EC2 → RDS)
    """
    connections = []
    seen = set()
    
    # Build reverse lookup: sg_id -> resources using it
    sg_to_resources: Dict[str, List[str]] = defaultdict(list)
    for res_id, res in resources.items():
        for sg in res.security_groups:
            sg_to_resources[sg].append(res_id)
    
    # 1. Security group based connections
    for sg_id, sg_info in security_groups.items():
        ingress_rules = sg_info.get("ingress", [])
        if not isinstance(ingress_rules, list):
            ingress_rules = [ingress_rules]
        
        for rule in ingress_rules:
            if not isinstance(rule, dict):
                continue
            
            # Check if ingress allows traffic from another security group
            source_sgs = rule.get("security_groups", [])
            if isinstance(source_sgs, list):
                for source_sg in source_sgs:
                    source_ref = extract_ref(source_sg)
                    if source_ref and source_ref in sg_to_resources:
                        # Resources in source_sg can connect to resources in sg_id
                        for from_res in sg_to_resources.get(source_ref, []):
                            for to_res in sg_to_resources.get(sg_id, []):
                                if from_res != to_res:
                                    key = (from_res, to_res)
                                    if key not in seen:
                                        seen.add(key)
                                        connections.append(Connection(from_res, to_res, "security_group"))
    
    # 2. Infer from architectural patterns
    public_resources = [r for r in resources.values() if r.tier == "public" and r.resource_type not in SKIP_RESOURCES]
    private_resources = [r for r in resources.values() if r.tier == "private" and r.resource_type not in SKIP_RESOURCES]
    compute_resources = [r for r in resources.values() if r.category == "compute" and r.resource_type not in SKIP_RESOURCES]
    
    # Pattern: Load Balancer → Compute
    for res in resources.values():
        if res.resource_type in {"aws_lb", "aws_alb", "aws_elb"}:
            # Find compute resources (EC2, ECS, Lambda)
            for compute in compute_resources:
                if compute.tier in {"public", "unknown"}:  # LB typically routes to public/compute tier
                    key = (res.id, compute.id)
                    if key not in seen:
                        seen.add(key)
                        connections.append(Connection(res.id, compute.id, "implicit"))
    
    # Pattern: Compute → Database
    for compute in compute_resources:
        for db in private_resources:
            if db.category == "database":
                key = (compute.id, db.id)
                if key not in seen:
                    seen.add(key)
                    connections.append(Connection(compute.id, db.id, "implicit"))
    
    # Pattern: API Gateway → Lambda
    for res in resources.values():
        if res.resource_type in {"aws_api_gateway_rest_api", "aws_apigatewayv2_api"}:
            for compute in compute_resources:
                if compute.resource_type == "aws_lambda_function":
                    key = (res.id, compute.id)
                    if key not in seen:
                        seen.add(key)
                        connections.append(Connection(res.id, compute.id, "implicit"))
    
    return connections


# =============================================================================
# LAYOUT ENGINE
# =============================================================================

def layout_resources(
    resources: Dict[str, Resource],
    connections: List[Connection],
    group_by_tier: bool = True
) -> dict:
    """
    Layout resources for SVG rendering.
    
    Detects if architecture uses VPC or is serverless and layouts accordingly.
    """
    # Filter out skip resources
    visible = {k: v for k, v in resources.items() if v.resource_type not in SKIP_RESOURCES}
    
    if not visible:
        return {"positions": {}, "tiers": {}, "vpc": None, "width": 400, "height": 300, "is_serverless": True}
    
    # Detect if this is a VPC-based or serverless architecture
    has_vpc_resources = any(r.resource_type in VPC_RESOURCES for r in visible.values())
    
    positions = {}
    tier_bounds = {}
    vpc_bounds = None
    
    if has_vpc_resources and group_by_tier:
        # VPC-based architecture - group by public/private subnet
        by_tier = defaultdict(list)
        for res in visible.values():
            # Only VPC resources go in tiers
            if res.resource_type in VPC_RESOURCES:
                by_tier[res.tier].append(res)
            else:
                # Serverless resources in a VPC architecture go in "external" tier
                by_tier["external"].append(res)
        
        # Order: external (edge services), public, private
        tier_order = ["external", "public", "private"]
        tiers_present = [t for t in tier_order if by_tier.get(t)]
        
        VPC_PAD = 16
        y = CANVAS_PAD + 6 * GRID  # Space for title
        vpc_start_y = y
        max_w = 0
        
        # Calculate max width
        max_tier_w = 0
        for tier_name in tiers_present:
            tier_resources = by_tier[tier_name]
            if tier_resources:
                num_nodes = len(tier_resources)
                content_w = num_nodes * NODE_W + (num_nodes - 1) * H_GAP
                tier_w = content_w + MODULE_PAD * 2
                max_tier_w = max(max_tier_w, tier_w)
        
        # Layout tiers
        vpc_tiers = []  # Track which tiers are inside VPC
        for tier_name in tiers_present:
            tier_resources = by_tier[tier_name]
            if not tier_resources:
                continue
            
            tier_resources.sort(key=lambda r: (r.category, r.name))
            
            tier_w = max_tier_w
            tier_h = NODE_H + MODULE_PAD * 2 + MODULE_HDR
            tier_x = CANVAS_PAD + USER_W + VPC_PAD if tier_name != "external" else CANVAS_PAD + USER_W
            
            # Labels
            if tier_name == "public":
                label = "Public Subnet"
                vpc_tiers.append(tier_name)
            elif tier_name == "private":
                label = "Private Subnet"
                vpc_tiers.append(tier_name)
            elif tier_name == "external":
                label = "Edge Services"
            else:
                label = "Resources"
            
            tier_bounds[tier_name] = {
                "x": tier_x, "y": y, "w": tier_w, "h": tier_h,
                "label": label, "in_vpc": tier_name in ["public", "private"]
            }
            
            # Position nodes
            num_nodes = len(tier_resources)
            actual_content_w = num_nodes * NODE_W + (num_nodes - 1) * H_GAP
            start_offset = (tier_w - actual_content_w) // 2
            
            node_y = y + MODULE_HDR + MODULE_PAD
            node_x = tier_x + start_offset
            
            for res in tier_resources:
                positions[res.id] = Position(x=node_x, y=node_y)
                node_x += NODE_W + H_GAP
            
            max_w = max(max_w, tier_x + tier_w)
            y += tier_h + V_GAP
        
        # Create VPC bounds only around VPC tiers
        if vpc_tiers:
            vpc_tier_bounds = [tier_bounds[t] for t in vpc_tiers if t in tier_bounds]
            if vpc_tier_bounds:
                vpc_x = CANVAS_PAD + USER_W
                vpc_y = min(t["y"] for t in vpc_tier_bounds) - MODULE_HDR - VPC_PAD
                vpc_bottom = max(t["y"] + t["h"] for t in vpc_tier_bounds)
                vpc_w = max_tier_w + VPC_PAD * 2
                vpc_h = vpc_bottom - vpc_y + VPC_PAD
                
                vpc_bounds = {
                    "x": vpc_x, "y": vpc_y, "w": vpc_w, "h": vpc_h,
                    "label": "VPC"
                }
    
    else:
        # Serverless architecture - simple flow layout, no VPC
        all_resources = sorted(visible.values(), key=lambda r: (
            # Sort by typical flow order
            0 if r.resource_type in {"aws_cloudfront_distribution", "aws_wafv2_web_acl"} else
            1 if r.resource_type in {"aws_api_gateway_rest_api", "aws_apigatewayv2_api", "aws_route53_zone"} else
            2 if r.resource_type in {"aws_lambda_function", "aws_lambda_function_url"} else
            3 if r.resource_type == "aws_s3_bucket" else
            4 if r.resource_type == "aws_dynamodb_table" else
            5,
            r.name
        ))
        
        # Single row or wrap to multiple rows
        MAX_PER_ROW = 6
        rows = [all_resources[i:i+MAX_PER_ROW] for i in range(0, len(all_resources), MAX_PER_ROW)]
        
        y = CANVAS_PAD + 6 * GRID
        max_w = 0
        
        for row in rows:
            x = CANVAS_PAD + USER_W + H_GAP
            for res in row:
                positions[res.id] = Position(x=x, y=y)
                x += NODE_W + H_GAP
            max_w = max(max_w, x)
            y += NODE_H + V_GAP * 2
    
    # Calculate user position
    if positions:
        first_pos = list(positions.values())[0]
        user_y = first_pos.y
    else:
        user_y = CANVAS_PAD + 100
    
    return {
        "positions": positions,
        "tiers": tier_bounds,
        "vpc": vpc_bounds,
        "user": Position(x=CANVAS_PAD, y=user_y, w=48, h=60),
        "width": max_w + CANVAS_PAD,
        "height": y + CANVAS_PAD,
        "is_serverless": not has_vpc_resources,
    }


# =============================================================================
# SVG GENERATION
# =============================================================================

def svg_defs() -> str:
    return f'''  <defs>
    <marker id="arrow" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
      <path d="M0,0 L0,6 L8,3 z" fill="{COLORS['arrow']}"/>
    </marker>
    <filter id="shadow" x="-20%" y="-20%" width="140%" height="140%">
      <feDropShadow dx="0" dy="2" stdDeviation="3" flood-opacity="0.1"/>
    </filter>
  </defs>'''


def svg_vpc(bounds: dict) -> str:
    """Render VPC container."""
    x, y, w, h = bounds["x"], bounds["y"], bounds["w"], bounds["h"]
    label = bounds.get("label", "VPC")
    
    return f'''  <g class="vpc">
    <rect x="{x}" y="{y}" width="{w}" height="{h}" fill="#fafafa" stroke="#232f3e" stroke-width="2" rx="8" stroke-dasharray="8,4"/>
    <rect x="{x}" y="{y}" width="{w}" height="{MODULE_HDR}" fill="#232f3e" rx="8"/>
    <rect x="{x}" y="{y + MODULE_HDR - 8}" width="{w}" height="8" fill="#232f3e"/>
    <text x="{x + 16}" y="{y + 21}" font-size="13" font-weight="600" fill="#ffffff">{label}</text>
  </g>'''


def svg_tier(name: str, bounds: dict) -> str:
    """Render a tier container (Public/Private)."""
    x, y, w, h = bounds["x"], bounds["y"], bounds["w"], bounds["h"]
    label = bounds.get("label", name)
    
    # Use different background colors for public vs private
    if "public" in name.lower():
        bg_color = COLORS["public_subnet"]
    elif "private" in name.lower():
        bg_color = COLORS["private_subnet"]
    else:
        bg_color = COLORS["module_bg"]
    
    return f'''  <g class="tier">
    <rect x="{x}" y="{y}" width="{w}" height="{h}" fill="{bg_color}" stroke="{COLORS['module_border']}" rx="8"/>
    <rect x="{x}" y="{y}" width="{w}" height="{MODULE_HDR}" fill="{COLORS['module_header']}" rx="8"/>
    <rect x="{x}" y="{y + MODULE_HDR - 8}" width="{w}" height="8" fill="{COLORS['module_header']}"/>
    <text x="{x + 16}" y="{y + 21}" font-size="13" font-weight="600" fill="#ffffff">{label}</text>
  </g>'''


def svg_node(resource: Resource, pos: Position, icons_dir: Optional[Path] = None) -> str:
    """Render a resource node with optional external icon."""
    color = CATEGORY_COLORS.get(resource.category, "#888888")
    
    # Icon area
    icon_x = pos.x + (pos.w - 48) // 2
    icon_y = pos.y + 12
    
    # Try to load external icon
    icon_svg = None
    if icons_dir:
        icon_svg = load_icon(resource.resource_type, icons_dir)
    
    if icon_svg:
        # Use external icon
        icon_content = f'''    <g transform="translate({icon_x},{icon_y}) scale(0.75)">
{icon_svg}
    </g>'''
    else:
        # Fallback to colored box with label
        icon_content = f'''    <rect x="{icon_x}" y="{icon_y}" width="48" height="48" rx="6" fill="{color}"/>
    <text x="{pos.cx}" y="{icon_y + 32}" font-size="14" font-weight="600" fill="white" text-anchor="middle">{resource.short_label}</text>'''
    
    return f'''  <g class="node">
    <rect x="{pos.x}" y="{pos.y}" width="{pos.w}" height="{pos.h}" fill="{COLORS['node_bg']}" stroke="{COLORS['node_border']}" rx="6" filter="url(#shadow)"/>
{icon_content}
    <text x="{pos.cx}" y="{pos.y + 76}" font-size="9" fill="{COLORS['text_secondary']}" text-anchor="middle">{resource.display_name}</text>
    <text x="{pos.cx}" y="{pos.y + 90}" font-size="11" fill="{COLORS['text']}" text-anchor="middle">{resource.name}</text>
  </g>'''


def load_icon(resource_type: str, icons_dir: Path) -> Optional[str]:
    """Load SVG icon from icons directory (searches recursively)."""
    # Map resource types to icon filename patterns
    ICON_PATTERNS = {
        "aws_instance": "Arch_Amazon-EC2_48",
        "aws_lb": "Arch_Elastic-Load-Balancing_48",
        "aws_alb": "Arch_Elastic-Load-Balancing_48",
        "aws_db_instance": "Arch_Amazon-RDS_48",
        "aws_rds_cluster": "Arch_Amazon-Aurora_48",
        "aws_dynamodb_table": "Arch_Amazon-DynamoDB_48",
        "aws_lambda_function": "Arch_AWS-Lambda_48",
        "aws_lambda_function_url": "Arch_AWS-Lambda_48",
        "aws_s3_bucket": "Arch_Amazon-Simple-Storage-Service_48",
        "aws_cloudfront_distribution": "Arch_Amazon-CloudFront_48",
        "aws_route53_zone": "Arch_Amazon-Route-53_48",
        "aws_route53_record": "Arch_Amazon-Route-53_48",
        "aws_api_gateway_rest_api": "Arch_Amazon-API-Gateway_48",
        "aws_apigatewayv2_api": "Arch_Amazon-API-Gateway_48",
        "aws_wafv2_web_acl": "Arch_AWS-WAF_48",
        "aws_acm_certificate": "Arch_AWS-Certificate-Manager_48",
        "aws_sqs_queue": "Arch_Amazon-Simple-Queue-Service_48",
        "aws_sns_topic": "Arch_Amazon-Simple-Notification-Service_48",
        "aws_ecs_cluster": "Arch_Amazon-Elastic-Container-Service_48",
        "aws_ecs_service": "Arch_Amazon-Elastic-Container-Service_48",
        "aws_eks_cluster": "Arch_Amazon-Elastic-Kubernetes-Service_48",
        "aws_elasticache_cluster": "Arch_Amazon-ElastiCache_48",
        "aws_efs_file_system": "Arch_Amazon-Elastic-File-System_48",
    }
    
    pattern = ICON_PATTERNS.get(resource_type)
    if not pattern:
        return None
    
    # Search recursively for the icon file
    for svg_file in icons_dir.rglob(f"{pattern}.svg"):
        try:
            content = svg_file.read_text()
            # Extract just the content inside <svg>...</svg>
            match = re.search(r'<svg[^>]*>(.*)</svg>', content, re.DOTALL)
            if match:
                return match.group(1)
        except Exception:
            continue
    
    return None


def svg_arrow(from_pos: Position, to_pos: Position, tier_bounds: dict = None) -> str:
    """Draw orthogonal arrow between nodes, respecting boundaries."""
    
    # Determine if same row (horizontal) or different rows (vertical)
    same_row = abs(from_pos.cy - to_pos.cy) < GRID * 2
    
    if same_row:
        # Horizontal arrow - straight line
        x1 = from_pos.right + ARROW_GAP
        y1 = from_pos.cy
        x2 = to_pos.left - ARROW_GAP
        y2 = to_pos.cy
        return f'  <line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{COLORS["arrow"]}" stroke-width="1.5" marker-end="url(#arrow)"/>'
    
    else:
        # Vertical connection - orthogonal routing
        # Start from bottom of source, end at top of target
        x1 = from_pos.cx
        y1 = from_pos.y + from_pos.h + ARROW_GAP
        x2 = to_pos.cx
        y2 = to_pos.y - ARROW_GAP
        
        # Route: go down, then horizontal, then down to target
        # Find the gap between tiers (midpoint)
        mid_y = y1 + (y2 - y1) // 2
        
        if x1 == x2:
            # Straight vertical line
            return f'  <path d="M{x1},{y1} L{x2},{y2}" fill="none" stroke="{COLORS["arrow"]}" stroke-width="1.5" marker-end="url(#arrow)"/>'
        else:
            # L-shaped or Z-shaped route
            return f'  <path d="M{x1},{y1} L{x1},{mid_y} L{x2},{mid_y} L{x2},{y2}" fill="none" stroke="{COLORS["arrow"]}" stroke-width="1.5" marker-end="url(#arrow)"/>'


def svg_user_arrow(user_pos: Position, target_pos: Position) -> str:
    """Draw curved line from user to entry point."""
    x1 = user_pos.right
    y1 = user_pos.cy
    x2 = target_pos.left - ARROW_GAP
    y2 = target_pos.cy
    
    ctrl_x = x1 + 24
    return f'  <path d="M{x1},{y1} C{ctrl_x},{y1} {ctrl_x},{y2} {x2},{y2}" fill="none" stroke="{COLORS["arrow"]}" stroke-width="1.5"/>'


def svg_user(pos: Position) -> str:
    return f'''  <g class="user" transform="translate({pos.x},{pos.y})">
    <circle cx="24" cy="12" r="9" fill="none" stroke="{COLORS['user']}" stroke-width="2"/>
    <path d="M8,38 Q8,24 24,24 Q40,24 40,38" fill="none" stroke="{COLORS['user']}" stroke-width="2"/>
    <text x="24" y="54" font-size="11" fill="{COLORS['text']}" text-anchor="middle">Users</text>
  </g>'''


def generate_svg(
    resources: Dict[str, Resource],
    connections: List[Connection],
    layout: dict,
    title: Optional[str] = None,
    show_user: bool = True,
    icons_dir: Optional[Path] = None
) -> str:
    """Generate complete SVG."""
    positions = layout["positions"]
    tiers = layout["tiers"]
    vpc = layout.get("vpc")
    width = layout["width"]
    height = layout["height"]
    user_pos = layout.get("user")
    
    parts = [
        f'<?xml version="1.0" encoding="UTF-8"?>',
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}"',
        f'     style="font-family: -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif;">',
        svg_defs(),
        f'  <rect width="100%" height="100%" fill="{COLORS["bg"]}"/>',
    ]
    
    # Title
    if title:
        parts.append(f'  <text x="{CANVAS_PAD}" y="{CANVAS_PAD + 4 * GRID}" font-size="18" font-weight="600" fill="{COLORS["text"]}">{title}</text>')
    
    # VPC container (render first so it's behind everything)
    if vpc:
        parts.append(svg_vpc(vpc))
    
    # Subnet tiers
    for tier_name, bounds in tiers.items():
        parts.append(svg_tier(tier_name, bounds))
    
    # Nodes
    for res_id, pos in positions.items():
        if res_id in resources:
            parts.append(svg_node(resources[res_id], pos, icons_dir))
    
    # Connections
    for conn in connections:
        if conn.from_id in positions and conn.to_id in positions:
            parts.append(svg_arrow(positions[conn.from_id], positions[conn.to_id], tiers))
    
    # User
    if show_user and user_pos and positions:
        parts.append(svg_user(user_pos))
        
        # Connect user to first public resource
        public_entries = [
            res_id for res_id, res in resources.items()
            if res.tier == "public" and res_id in positions
        ]
        if public_entries:
            parts.append(svg_user_arrow(user_pos, positions[public_entries[0]]))
    
    parts.append('</svg>')
    return '\n'.join(parts)


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='Generate AWS architecture diagram from Terraform .tf files',
        epilog='Example: python files2svg.py ./terraform/ arch.svg --title "My Infrastructure" --icons ./icons'
    )
    parser.add_argument('input', help='Directory containing .tf files')
    parser.add_argument('output', help='Output SVG file')
    parser.add_argument('--title', help='Diagram title')
    parser.add_argument('--icons', help='Path to AWS icons directory')
    parser.add_argument('--flat', action='store_true', help='Flat layout (no tier grouping)')
    parser.add_argument('--no-user', action='store_true', help='Hide user icon')
    
    args = parser.parse_args()
    
    tf_dir = Path(args.input)
    if not tf_dir.is_dir():
        print(f"Error: {args.input} is not a directory", file=sys.stderr)
        sys.exit(1)
    
    icons_dir = Path(args.icons) if args.icons else None
    if icons_dir and not icons_dir.is_dir():
        print(f"Warning: Icons directory {args.icons} not found, using fallback icons", file=sys.stderr)
        icons_dir = None
    
    # Parse
    print(f"Parsing .tf files in {tf_dir}...", file=sys.stderr)
    resources, security_groups, subnets = parse_tf_files(tf_dir)
    
    if not resources:
        print("Warning: No resources found", file=sys.stderr)
    
    # Filter
    visible = {k: v for k, v in resources.items() if v.resource_type not in SKIP_RESOURCES}
    
    # Infer connections
    connections = infer_connections(resources, security_groups)
    
    # Filter connections to visible resources only
    connections = [c for c in connections if c.from_id in visible and c.to_id in visible]
    
    # Layout
    layout = layout_resources(resources, connections, group_by_tier=not args.flat)
    
    # Generate
    svg = generate_svg(visible, connections, layout, args.title, not args.no_user, icons_dir)
    Path(args.output).write_text(svg)
    
    # Stats
    print(f"✓ {args.output}", file=sys.stderr)
    print(f"  {len(visible)} resources, {len(connections)} connections", file=sys.stderr)
    
    by_tier = defaultdict(int)
    for res in visible.values():
        by_tier[res.tier] += 1
    print(f"  Tiers: {dict(by_tier)}", file=sys.stderr)


if __name__ == "__main__":
    main()