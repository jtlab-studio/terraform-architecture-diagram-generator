#!/usr/bin/env python3
"""
graph2svg - Professional AWS Architecture Diagram Generator

LAYOUT PHILOSOPHY:
Resources are organized by their FLOW PATH - the logical path data takes through them.
This creates multi-row modules where each row represents a distinct flow:

  Row 0: CDN Flow      → DNS → WAF → CloudFront → S3
  Row 1: Compute Flow  → API/URL → Lambda → DynamoDB
  Row 2: Support       → ACM, KMS (no data flow)

UNIVERSAL RULES:
1. Resources are classified by FLOW PATH, not just service type
2. Each flow path gets its own row within a module
3. Support services (certs, auth) are shown but not connected
4. User arrows connect to the FIRST node of each flow path
5. Arrows only flow left-to-right within a row

Usage:
    terraform graph | python graph2svg.py - output.svg
    terraform graph | python graph2svg.py - output.svg --title "My Infra" --icons ./icons
"""

import sys
import re
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass, field

# =============================================================================
# DESIGN SYSTEM (8px grid)
# =============================================================================

GRID = 8

ICON_SIZE = 48
NODE_W = 14 * GRID      # 112px
NODE_H = 13 * GRID      # 104px
H_GAP = 6 * GRID        # 48px between nodes
V_GAP = 3 * GRID        # 24px between rows within module
MODULE_GAP = 10 * GRID  # 80px between modules
MODULE_PAD = 3 * GRID   # 24px
MODULE_HDR = 4 * GRID   # 32px
CANVAS_PAD = 8 * GRID   # 64px
USER_W = 10 * GRID      # 80px
ARROW_GAP = GRID        # 8px

COLORS = {
    "bg": "#ffffff",
    "module_bg": "#f8f9fa",
    "module_border": "#e9ecef",
    "module_hdr": "#232f3e",
    "node_bg": "#ffffff",
    "node_border": "#d5dbdb",
    "text": "#232f3e",
    "text2": "#545b64",
    "text_inv": "#ffffff",
    "arrow": "#545b64",
    "user": "#232f3e",
    "compute": "#ED7100",
    "database": "#C925D1",
    "storage": "#7AA116",
    "network": "#8C4FFF",
    "security": "#DD344C",
    "integration": "#E7157B",
    "default": "#879196",
}

# =============================================================================
# FLOW PATH CLASSIFICATION (Universal Rules)
# =============================================================================

# Each resource is assigned to a FLOW PATH and a POSITION within that flow
# Format: (flow_path, position_in_flow)
# 
# Flow paths:
#   "cdn"     - Static content delivery: DNS → Protection → CDN → Storage
#   "api"     - API-based: API Gateway/ALB → Compute → Database
#   "compute" - Direct compute: Function URL → Compute → Database
#   "support" - Supporting services: Certs, Auth (no data flow through them)

FLOW_PATHS = {
    # CDN Flow: DNS → Protection → CDN → Storage
    "aws_route53_zone":           ("cdn", 0),      # DNS entry
    "aws_wafv2_web_acl":          ("cdn", 1),      # Protection layer
    "aws_cloudfront_distribution": ("cdn", 2),     # CDN routing
    "aws_s3_bucket":              ("cdn", 3),      # Origin storage
    
    # API Flow: API Gateway → Compute → Database
    "aws_api_gateway_rest_api":   ("api", 0),      # API entry
    "aws_apigatewayv2_api":       ("api", 0),      # API entry (v2)
    "aws_lb":                     ("api", 0),      # Load balancer entry
    "aws_alb":                    ("api", 0),      # ALB entry
    
    # Compute Flow: Function URL → Compute → Queue → Database
    "aws_lambda_function_url":    ("compute", 0),  # Direct function entry
    "aws_lambda_function":        ("compute", 1),  # Compute
    "aws_ecs_service":            ("compute", 1),  # Compute
    "aws_ecs_cluster":            ("compute", 1),  # Compute
    "aws_eks_cluster":            ("compute", 1),  # Compute
    "aws_instance":               ("compute", 1),  # Compute (EC2)
    "aws_sqs_queue":              ("compute", 2),  # Messaging
    "aws_sns_topic":              ("compute", 2),  # Messaging
    "aws_eventbridge_rule":       ("compute", 2),  # Events
    "aws_kinesis_stream":         ("compute", 2),  # Streaming
    "aws_sfn_state_machine":      ("compute", 2),  # Orchestration
    "aws_dynamodb_table":         ("compute", 3),  # Database
    "aws_db_instance":            ("compute", 3),  # Database
    "aws_rds_cluster":            ("compute", 3),  # Database
    "aws_elasticache_cluster":    ("compute", 3),  # Cache
    "aws_efs_file_system":        ("compute", 3),  # Storage
    
    # Support Flow: No data flow, just configuration
    "aws_acm_certificate":        ("support", 0),  # TLS certs
    "aws_cognito_user_pool":      ("support", 1),  # Auth
}

# Flow path display order (top to bottom within module)
FLOW_ORDER = ["cdn", "api", "compute", "support"]

# Entry points - first node of each flow that users connect to
FLOW_ENTRIES = {
    "cdn": {"aws_route53_zone"},
    "api": {"aws_api_gateway_rest_api", "aws_apigatewayv2_api", "aws_lb", "aws_alb"},
    "compute": {"aws_lambda_function_url"},
    "support": set(),  # No user entry to support services
}

# Resources to skip entirely
SKIP_RESOURCES = {
    "aws_route53_record",
    "aws_lb_target_group", "aws_lb_listener",
    "aws_security_group", "aws_security_group_rule",
    "aws_iam_role", "aws_iam_policy", "aws_iam_role_policy_attachment",
    "aws_cloudwatch_log_group", "aws_lambda_permission",
    "aws_s3_bucket_policy", "aws_s3_bucket_public_access_block",
    "aws_acm_certificate_validation",
}

# Support services - shown but no flow arrows
SUPPORT_SERVICES = {"aws_acm_certificate", "aws_cognito_user_pool"}

# Service display info: (label, abbreviation, color_category)
SERVICE_INFO = {
    "aws_lambda_function": ("Lambda", "λ", "compute"),
    "aws_lambda_function_url": ("Lambda URL", "λ", "compute"),
    "aws_dynamodb_table": ("DynamoDB", "DDB", "database"),
    "aws_s3_bucket": ("S3", "S3", "storage"),
    "aws_cloudfront_distribution": ("CloudFront", "CF", "network"),
    "aws_route53_zone": ("Route 53", "R53", "network"),
    "aws_api_gateway_rest_api": ("API Gateway", "API", "network"),
    "aws_apigatewayv2_api": ("API Gateway", "API", "network"),
    "aws_lb": ("Load Balancer", "ALB", "network"),
    "aws_alb": ("Load Balancer", "ALB", "network"),
    "aws_acm_certificate": ("ACM Cert", "ACM", "security"),
    "aws_wafv2_web_acl": ("WAF", "WAF", "security"),
    "aws_cognito_user_pool": ("Cognito", "COG", "security"),
    "aws_sqs_queue": ("SQS", "SQS", "integration"),
    "aws_sns_topic": ("SNS", "SNS", "integration"),
    "aws_ecs_service": ("ECS", "ECS", "compute"),
    "aws_ecs_cluster": ("ECS", "ECS", "compute"),
    "aws_eks_cluster": ("EKS", "EKS", "compute"),
    "aws_instance": ("EC2", "EC2", "compute"),
    "aws_db_instance": ("RDS", "RDS", "database"),
    "aws_rds_cluster": ("Aurora", "RDS", "database"),
    "aws_elasticache_cluster": ("ElastiCache", "EC", "database"),
    "aws_sfn_state_machine": ("Step Functions", "SFN", "integration"),
    "aws_eventbridge_rule": ("EventBridge", "EB", "integration"),
    "aws_kinesis_stream": ("Kinesis", "KIN", "integration"),
    "aws_efs_file_system": ("EFS", "EFS", "storage"),
}

# Icon file mapping
ICON_FILES = {
    "aws_lambda_function": "Arch_AWS-Lambda_48.svg",
    "aws_lambda_function_url": "Arch_AWS-Lambda_48.svg",
    "aws_dynamodb_table": "Arch_Amazon-DynamoDB_48.svg",
    "aws_s3_bucket": "Arch_Amazon-Simple-Storage-Service_48.svg",
    "aws_cloudfront_distribution": "Arch_Amazon-CloudFront_48.svg",
    "aws_route53_zone": "Arch_Amazon-Route-53_48.svg",
    "aws_api_gateway_rest_api": "Arch_Amazon-API-Gateway_48.svg",
    "aws_apigatewayv2_api": "Arch_Amazon-API-Gateway_48.svg",
    "aws_lb": "Arch_Elastic-Load-Balancing_48.svg",
    "aws_alb": "Arch_Elastic-Load-Balancing_48.svg",
    "aws_acm_certificate": "Arch_AWS-Certificate-Manager_48.svg",
    "aws_wafv2_web_acl": "Arch_AWS-WAF_48.svg",
    "aws_cognito_user_pool": "Arch_Amazon-Cognito_48.svg",
    "aws_sqs_queue": "Arch_Amazon-Simple-Queue-Service_48.svg",
    "aws_sns_topic": "Arch_Amazon-Simple-Notification-Service_48.svg",
    "aws_ecs_service": "Arch_Amazon-Elastic-Container-Service_48.svg",
    "aws_ecs_cluster": "Arch_Amazon-Elastic-Container-Service_48.svg",
    "aws_eks_cluster": "Arch_Amazon-Elastic-Kubernetes-Service_48.svg",
    "aws_instance": "Arch_Amazon-EC2_48.svg",
    "aws_db_instance": "Arch_Amazon-RDS_48.svg",
    "aws_rds_cluster": "Arch_Amazon-Aurora_48.svg",
    "aws_elasticache_cluster": "Arch_Amazon-ElastiCache_48.svg",
    "aws_sfn_state_machine": "Arch_AWS-Step-Functions_48.svg",
    "aws_eventbridge_rule": "Arch_Amazon-EventBridge_48.svg",
    "aws_kinesis_stream": "Arch_Amazon-Kinesis_48.svg",
    "aws_efs_file_system": "Arch_Amazon-Elastic-File-System_48.svg",
}


# =============================================================================
# DATA STRUCTURES
# =============================================================================

@dataclass
class Node:
    id: str
    address: str
    resource_type: str
    name: str
    module: Optional[str] = None
    flow: str = "compute"
    position: int = 0
    
    def __post_init__(self):
        if self.resource_type in FLOW_PATHS:
            self.flow, self.position = FLOW_PATHS[self.resource_type]


@dataclass
class Edge:
    from_id: str
    to_id: str


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
# DOT PARSER
# =============================================================================

def parse_dot(content: str) -> Tuple[Dict[str, Node], List[Edge]]:
    """Parse terraform graph DOT output."""
    nodes: Dict[str, Node] = {}
    edges: List[Edge] = []
    
    edge_re = re.compile(r'"([^"]+)"\s*->\s*"([^"]+)"')
    
    for line in content.split('\n'):
        match = edge_re.search(line)
        if not match:
            continue
            
        src, tgt = match.groups()
        
        for node_str in [src, tgt]:
            if node_str not in nodes:
                node = parse_node(node_str)
                if node:
                    nodes[node.id] = node
        
        if src in nodes and tgt in nodes:
            edges.append(Edge(src, tgt))
    
    return nodes, edges


def parse_node(s: str) -> Optional[Node]:
    """Parse node string from DOT."""
    if 'provider[' in s or '[root] root' in s:
        return None
    if 'provisioner' in s or 'var.' in s or 'local.' in s:
        return None
    if 'data.' in s or 'output.' in s:
        return None
    
    clean = s.replace('[root] ', '').strip()
    clean = re.sub(r'\s*\(expand\)\s*$', '', clean)
    
    module = None
    resource_part = clean
    
    if clean.startswith('module.'):
        parts = clean.split('.')
        for i, part in enumerate(parts):
            if part.startswith('aws_'):
                module = '_'.join(parts[1:i])
                resource_part = '.'.join(parts[i:])
                break
        else:
            return None
    
    if '.' not in resource_part:
        return None
    
    rtype, name = resource_part.split('.', 1)
    
    if rtype in SKIP_RESOURCES:
        return None
    if rtype not in FLOW_PATHS:
        return None
    
    return Node(id=s, address=clean, resource_type=rtype, name=name, module=module)


def filter_edges(nodes: Dict[str, Node], edges: List[Edge]) -> Tuple[List[Edge], List[Edge]]:
    """
    Filter edges to show DATA FLOW (not Terraform dependencies).
    Returns: (intra_module_edges, cross_module_edges)
    - Skip edges involving support services
    - Reverse direction to show flow (TF deps are inverse of data flow)
    - Remove duplicates
    - Add implicit flow arrows for adjacent nodes in same flow path
    - Identify cross-module connections
    """
    visible = set(nodes.keys())
    intra_result = []
    cross_result = []
    seen = set()
    
    # First, collect explicit edges
    for e in edges:
        if e.from_id not in visible or e.to_id not in visible:
            continue
        
        from_node = nodes[e.from_id]
        to_node = nodes[e.to_id]
        
        # Skip edges involving support services
        if from_node.resource_type in SUPPORT_SERVICES:
            continue
        if to_node.resource_type in SUPPORT_SERVICES:
            continue
        
        # Check if cross-module
        is_cross_module = from_node.module != to_node.module
        
        # For same-module, skip cross-flow edges
        if not is_cross_module and from_node.flow != to_node.flow:
            continue
        
        # Determine visual direction (reverse TF dependency to show data flow)
        if from_node.position > to_node.position:
            visual_from, visual_to = e.to_id, e.from_id
        else:
            visual_from, visual_to = e.from_id, e.to_id
        
        edge_key = (visual_from, visual_to)
        if edge_key not in seen:
            seen.add(edge_key)
            if is_cross_module:
                cross_result.append(Edge(visual_from, visual_to))
            else:
                intra_result.append(Edge(visual_from, visual_to))
    
    # Second, add implicit flow arrows for adjacent positions in same flow
    # Group nodes by (module, flow)
    by_module_flow: Dict[Tuple[str, str], List[Node]] = defaultdict(list)
    for node in nodes.values():
        if node.resource_type not in SUPPORT_SERVICES:
            key = (node.module or "_root", node.flow)
            by_module_flow[key].append(node)
    
    for (mod, flow), flow_nodes in by_module_flow.items():
        if len(flow_nodes) < 2:
            continue
        
        # Sort by position
        flow_nodes.sort(key=lambda n: (n.position, n.name))
        
        # Connect adjacent nodes
        for i in range(len(flow_nodes) - 1):
            from_node = flow_nodes[i]
            to_node = flow_nodes[i + 1]
            
            edge_key = (from_node.id, to_node.id)
            if edge_key not in seen:
                seen.add(edge_key)
                intra_result.append(Edge(from_node.id, to_node.id))
    
    # Third, detect semantic cross-module connections
    # Rule: If module A has a CDN/routing endpoint and module B has a compute entry,
    # the website likely calls the API
    cdn_endpoints = []  # (node_id, module) - services that serve content
    api_entries = []    # (node_id, module) - services that receive API calls
    
    for node in nodes.values():
        if node.resource_type in SUPPORT_SERVICES:
            continue
        mod = node.module or "_root"
        # CDN endpoints: S3 buckets serving websites, CloudFront distributions
        if node.resource_type in {"aws_s3_bucket", "aws_cloudfront_distribution"}:
            cdn_endpoints.append((node.id, mod))
        # API entries: Lambda URLs, API Gateways
        if node.resource_type in {"aws_lambda_function_url", "aws_api_gateway_rest_api", "aws_apigatewayv2_api"}:
            api_entries.append((node.id, mod))
    
    # Connect CDN endpoints to API entries in DIFFERENT modules
    for cdn_id, cdn_mod in cdn_endpoints:
        for api_id, api_mod in api_entries:
            if cdn_mod != api_mod:  # Cross-module only
                edge_key = (cdn_id, api_id)
                reverse_key = (api_id, cdn_id)
                if edge_key not in seen and reverse_key not in seen:
                    seen.add(edge_key)
                    # Website calls API, so arrow from website to API
                    cross_result.append(Edge(cdn_id, api_id))
    
    return intra_result, cross_result


# =============================================================================
# LAYOUT ENGINE
# =============================================================================

def layout(nodes: Dict[str, Node], title: str = None) -> dict:
    """
    Multi-row layout: each flow path gets its own row within a module.
    """
    # Group nodes by module
    by_module: Dict[str, List[Node]] = defaultdict(list)
    for node in nodes.values():
        by_module[node.module or "_root"].append(node)
    
    # Module order
    mod_order = []
    if "_root" in by_module:
        mod_order.append("_root")
    mod_order.extend(sorted(m for m in by_module if m != "_root"))
    
    positions: Dict[str, Position] = {}
    mod_bounds = {}
    entry_points = []  # (node_id, Position) for user arrows
    
    title_h = 6 * GRID if title else 0
    y = CANVAS_PAD + title_h
    max_w = 0
    
    for mod_name in mod_order:
        mod_nodes = by_module[mod_name]
        if not mod_nodes:
            continue
        
        # Group by flow path, sort by position within flow
        by_flow: Dict[str, List[Node]] = defaultdict(list)
        for node in mod_nodes:
            by_flow[node.flow].append(node)
        
        for flow in by_flow:
            by_flow[flow].sort(key=lambda n: (n.position, n.name))
        
        # Determine which flows are present (in display order)
        present_flows = [f for f in FLOW_ORDER if f in by_flow and by_flow[f]]
        
        if not present_flows:
            continue
        
        # Calculate module dimensions
        max_nodes_in_row = max(len(by_flow[f]) for f in present_flows)
        num_rows = len(present_flows)
        
        content_w = max_nodes_in_row * NODE_W + (max_nodes_in_row - 1) * H_GAP
        content_h = num_rows * NODE_H + (num_rows - 1) * V_GAP
        
        mod_w = content_w + MODULE_PAD * 2
        mod_h = content_h + MODULE_PAD * 2 + MODULE_HDR
        mod_x = CANVAS_PAD + USER_W
        
        mod_bounds[mod_name] = {
            "x": mod_x, "y": y, "w": mod_w, "h": mod_h,
            "label": mod_name.replace("_", " ").title() if mod_name != "_root" else "Root"
        }
        
        # Position nodes row by row
        row_y = y + MODULE_HDR + MODULE_PAD
        
        for flow in present_flows:
            flow_nodes = by_flow[flow]
            row_x = mod_x + MODULE_PAD
            
            # Track first node in flow for user arrow entry point
            first_node = flow_nodes[0] if flow_nodes else None
            
            for i, node in enumerate(flow_nodes):
                pos = Position(x=row_x, y=row_y)
                positions[node.id] = pos
                
                # Mark entry points
                if i == 0 and flow != "support":
                    entry_types = FLOW_ENTRIES.get(flow, set())
                    if node.resource_type in entry_types:
                        entry_points.append((node.id, pos))
                
                row_x += NODE_W + H_GAP
            
            row_y += NODE_H + V_GAP
        
        max_w = max(max_w, mod_x + mod_w)
        y += mod_h + MODULE_GAP
    
    canvas_h = y - MODULE_GAP + CANVAS_PAD
    user_y = CANVAS_PAD + title_h + (canvas_h - title_h - CANVAS_PAD * 2) // 2 - 30
    
    return {
        "positions": positions,
        "modules": mod_bounds,
        "entry_points": entry_points,
        "user": Position(x=CANVAS_PAD, y=user_y, w=48, h=60),
        "width": max_w + CANVAS_PAD,
        "height": canvas_h,
        "title_y": CANVAS_PAD + 4 * GRID if title else 0,
    }


# =============================================================================
# EMBEDDED AWS ICONS (extracted from official AWS Architecture Icons)
# =============================================================================

EMBEDDED_ICONS = {
    "aws_lambda_function": """<g id="Icon-Architecture/48/Arch_AWS-Lambda_48" stroke="none" stroke-width="1" fill="none" fill-rule="evenodd">
        <g id="Icon-Architecture-BG/48/Compute" fill="#ED7100">
            <rect id="Rectangle" x="0" y="0" width="64" height="64" rx="8"></rect>
        </g>
        <path d="M22.6794094,52 L13.5740701,52 L23.8376189,30.41 L28.3997494,39.861 L22.6794094,52 Z M24.7269406,27.667 C24.5606285,27.321 24.2120702,27.103 23.8306478,27.103 L23.8276601,27.103 C23.4452418,27.104 23.0966835,27.325 22.9323632,27.672 L11.0973143,52.569 C10.9499239,52.879 10.9708374,53.243 11.1540795,53.534 C11.3353298,53.824 11.6540117,54 11.9955989,54 L23.309802,54 C23.695208,54 24.0447622,53.777 24.2100784,53.428 L30.4044577,40.284 C30.5329264,40.01 30.5319305,39.692 30.3994783,39.42 L24.7269406,27.667 Z M51.0082382,52 L41.985557,52 L26.9547262,19.578 C26.7914017,19.226 26.4388599,19 26.0524581,19 L20.1279625,19 L20.1349337,12 L31.8146251,12 L46.7747483,44.42 C46.9380728,44.774 47.2906147,45 47.6790082,45 L51.0082382,45 L51.0082382,52 Z M52.0041191,43 L48.3143803,43 L33.354257,10.58 C33.1909326,10.226 32.8383907,10 32.450993,10 L19.1400486,10 C18.5913182,10 18.1451636,10.447 18.1441677,10.999 L18.1362006,19.999 C18.1362006,20.265 18.2407681,20.519 18.4269979,20.707 C18.6142235,20.895 18.8671772,21 19.1310857,21 L25.4170861,21 L40.4479168,53.422 C40.6112413,53.774 40.9627873,54 41.350185,54 L52.0041191,54 C52.5548412,54 53,53.552 53,53 L53,44 C53,43.448 52.5548412,43 52.0041191,43 L52.0041191,43 Z" id="AWS-Lambda_Icon_48_Squid" fill="#FFFFFF"></path>
    </g>""",
    
    "aws_dynamodb_table": """<g id="Icon-Architecture/48/Arch_Amazon-DynamoDB_48" stroke="none" stroke-width="1" fill="none" fill-rule="evenodd">
        <g id="Icon-Architecture-BG/48/Database" fill="#C925D1">
            <rect id="Rectangle" x="0" y="0" width="64" height="64" rx="8"></rect>
        </g>
        <path d="M46.586,25.249 L43.001,25.249 C42.673,25.249 42.366,25.087 42.179,24.815 C41.992,24.542 41.949,24.194 42.065,23.884 L44.558,17.162 L35.645,17.162 L31.554,26.26 L36.001,26.26 C36.322,26.26 36.624,26.416 36.813,26.681 C37,26.944 37.052,27.282 36.949,27.59 L33.289,38.691 L46.586,25.249 Z M49.707,24.953 L31.708,43.149 C31.516,43.344 31.259,43.445 31.001,43.445 C30.819,43.445 30.638,43.396 30.476,43.295 C30.081,43.048 29.905,42.56 30.053,42.115 L34.613,28.282 L30.001,28.282 C29.661,28.282 29.345,28.107 29.16,27.819 C28.977,27.529 28.95,27.166 29.091,26.853 L34.091,15.733 C34.253,15.372 34.608,15.14 35.001,15.14 L46.001,15.14 C46.329,15.14 46.636,15.303 46.823,15.575 C47.01,15.848 47.053,16.196 46.938,16.506 L44.444,23.227 L49,23.227 C49.404,23.227 49.77,23.474 49.924,23.851 C50.079,24.229 49.993,24.664 49.707,24.953 Z M41.001,44.22 C38.291,46.106 33.314,47.102 28.533,47.102 C23.717,47.102 18.696,46.093 16,44.178 L16.001,47.994 C16.001,49.658 20.769,51.978 28.533,51.978 C36.028,51.978 41.001,49.276 41.001,47.489 L41.001,44.22 Z M43.065,40.95 C43.065,41.137 43.033,41.317 43.001,41.496 L43.001,47.489 C43.001,51.08 36.511,54 28.533,54 C21.63,54 14.662,52.111 14.06,48.5 L14,43.445 L14,30.304 L14,16.151 L14.001,16.151 C14.001,12.155 21.488,10 28.533,10 C32.474,10 36.263,10.64 38.93,11.756 L38.164,13.624 C35.732,12.605 32.221,12.022 28.533,12.022 C20.769,12.022 16.001,14.427 16.001,16.151 C16.001,17.876 20.769,20.281 28.533,20.281 C28.728,20.281 28.932,20.282 29.129,20.274 L29.207,22.293 C28.982,22.303 28.758,22.303 28.533,22.303 C23.716,22.303 18.696,21.294 16,19.379 L16,23.737 L16.001,23.754 C16.006,24.284 16.49,24.897 17.365,25.474 C19.347,26.762 22.915,27.642 26.904,27.825 L26.813,29.845 C22.687,29.655 19.063,28.776 16.727,27.429 C16.417,27.727 16.001,28.485 16.001,28.896 C16.001,30.62 20.769,33.025 28.533,33.025 C29.271,33.025 29.998,33 30.695,32.95 L30.836,34.967 C30.092,35.021 29.317,35.047 28.533,35.047 C23.716,35.047 18.696,34.038 16,32.123 L16,35.793 L16.001,35.793 C16.006,36.34 16.49,36.953 17.365,37.53 C19.633,39.004 23.914,39.923 28.533,39.923 L28.863,39.923 L28.863,41.945 L28.533,41.945 C23.755,41.945 18.673,40.937 16.001,39.402 C15.679,39.7 16.001,40.413 16.001,40.95 C16.001,42.675 20.769,45.08 28.533,45.08 C36.298,45.08 41.065,42.675 41.065,40.95 C41.065,40.341 40.466,39.776 39.973,39.412 C39.564,39.659 39.114,39.895 38.601,40.111 L37.833,38.244 C38.364,38.021 38.823,37.781 39.197,37.533 C40.298,36.799 41.001,35.754 41.001,35.358 L43.001,35.358 C43.001,36.298 42.38,37.305 41.584,38.133 C42.776,39.173 43.065,40.211 43.065,40.95 Z" id="Amazon-DynamoDB_Icon_48_Squid" fill="#FFFFFF"></path>
    </g>""",
    
    "aws_route53_zone": """<g id="Icon-Architecture/48/Arch_Amazon-Route-53_48" stroke="none" stroke-width="1" fill="none" fill-rule="evenodd">
        <g id="Icon-Architecture-BG/48/Networking-Content-Delivery" fill="#8C4FFF">
            <rect id="Rectangle" x="0" y="0" width="64" height="64" rx="8"></rect>
        </g>
        <path d="M38.761,32.527 C39.336,33.058 39.623,33.77 39.623,34.664 C39.623,35.637 39.274,36.413 38.574,36.994 C37.875,37.575 36.935,37.865 35.754,37.865 C34.822,37.865 33.899,37.666 32.986,37.27 L32.986,36.078 C34.067,36.435 34.99,36.614 35.754,36.614 C36.508,36.614 37.088,36.445 37.495,36.108 C37.903,35.771 38.106,35.289 38.106,34.664 C38.106,33.463 37.347,32.862 35.828,32.862 C35.352,32.862 34.881,32.887 34.414,32.936 L34.414,31.953 L37.54,28.544 L33.134,28.544 L33.134,27.322 L39.193,27.322 L39.193,28.499 L36.126,31.745 C36.176,31.735 36.225,31.73 36.275,31.73 L36.424,31.73 C37.407,31.73 38.185,31.996 38.761,32.527 M30.114,32.266 C30.718,32.833 31.021,33.611 31.021,34.604 C31.021,35.577 30.668,36.363 29.964,36.965 C29.259,37.565 28.331,37.865 27.181,37.865 C26.169,37.865 25.221,37.666 24.338,37.27 L24.338,36.078 C25.44,36.435 26.382,36.614 27.166,36.614 C27.92,36.614 28.498,36.443 28.9,36.101 C29.302,35.758 29.502,35.265 29.502,34.619 C29.502,33.914 29.315,33.403 28.937,33.085 C28.56,32.768 27.945,32.609 27.091,32.609 C26.476,32.609 25.707,32.659 24.784,32.758 L24.784,31.775 L25.068,27.322 L30.5,27.322 L30.5,28.544 L26.318,28.544 L26.123,31.567 C26.669,31.467 27.16,31.417 27.597,31.417 C28.669,31.417 29.508,31.7 30.114,32.266 M41.261,42.964 C37.516,43.636 34.233,45.146 32,46.395 C29.768,45.146 26.485,43.636 22.74,42.964 C21.708,42.779 16.566,41.708 16.566,38.825 C16.566,37.463 17.063,36.542 18.017,34.9 C19.133,32.974 20.663,30.336 20.663,26.674 C20.663,24.11 20.004,21.651 18.703,19.353 C18.792,19.244 18.882,19.133 18.972,19.023 C20.927,19.972 22.959,20.453 25.025,20.453 C27.571,20.453 29.914,19.796 32,18.502 C34.086,19.796 36.43,20.453 38.976,20.453 C41.041,20.453 43.073,19.972 45.029,19.023 C45.118,19.133 45.208,19.244 45.297,19.353 C43.996,21.651 43.337,24.11 43.337,26.674 C43.337,30.336 44.867,32.974 45.984,34.9 C46.938,36.542 47.435,37.463 47.435,38.825 C47.435,41.708 42.292,42.779 41.261,42.964 M45.337,26.674 C45.337,24.259 46.019,21.944 47.362,19.792 C47.589,19.429 47.559,18.961 47.288,18.63 C46.893,18.145 46.479,17.636 46.07,17.13 C45.766,16.753 45.234,16.65 44.809,16.884 C42.926,17.924 40.963,18.452 38.976,18.452 C36.576,18.452 34.482,17.808 32.57,16.483 C32.228,16.245 31.773,16.245 31.431,16.483 C29.519,17.808 27.424,18.452 25.025,18.452 C23.037,18.452 21.074,17.924 19.192,16.884 C18.766,16.65 18.236,16.753 17.931,17.13 C17.522,17.636 17.108,18.145 16.712,18.63 C16.442,18.961 16.411,19.429 16.639,19.792 C17.982,21.944 18.663,24.259 18.663,26.674 C18.663,29.798 17.401,31.974 16.286,33.895 C15.22,35.734 14.566,36.956 14.566,38.825 C14.566,43.188 20.551,44.603 22.386,44.933 C26.136,45.607 29.41,47.198 31.497,48.412 C31.653,48.502 31.826,48.548 32,48.548 C32.174,48.548 32.348,48.502 32.503,48.412 C34.59,47.198 37.865,45.607 41.615,44.933 C43.449,44.603 49.435,43.188 49.435,38.825 C49.435,36.956 48.781,35.734 47.714,33.895 C46.6,31.974 45.337,29.798 45.337,26.674" id="Amazon-Route-53-Icon_48_Squid" fill="#FFFFFF"></path>
    </g>""",
    
    "aws_wafv2_web_acl": """<g id="Icon-Architecture/48/Arch_AWS-WAF_48" stroke="none" stroke-width="1" fill="none" fill-rule="evenodd">
        <g id="Icon-Architecture-BG/48/Security-Identity-Compliance" fill="#DD344C">
            <rect id="Rectangle" x="0" y="0" width="64" height="64" rx="8"></rect>
        </g>
        <g id="Icon-Service/48/AWS-WAF_48" transform="translate(10, 10)" fill="#FFFFFF">
            <path d="M16.929,30.397 C17.816,31.015 18.833,31.581 19.969,32.089 C19.492,29.713 19.175,25.602 21.312,21.671 C22.905,18.743 23.168,15.417 22,12.99 C21.548,12.05 20.9,11.28 20.078,10.698 C20.84,12.457 21.268,14.997 20.116,18.27 C19.984,18.644 19.645,18.904 19.249,18.935 C18.866,18.967 18.48,18.76 18.291,18.412 C17.96,17.796 17.049,16.408 16.008,15.579 C16.416,17.455 16.675,20.262 15.335,22.367 C15.263,22.48 15.197,22.59 15.134,22.701 C13.664,25.29 14.452,28.671 16.929,30.397 L16.929,30.397 Z M24.471,14.155 C25.036,16.804 24.563,19.88 23.07,22.626 C20.905,26.607 21.707,30.945 22.161,32.651 C24.117,32.322 29.063,31.094 30.119,27.002 C31.133,23.076 30.52,20.803 29.81,19.578 C29.101,22.122 27.802,23.193 27.735,23.247 C27.411,23.506 26.963,23.539 26.606,23.333 C26.248,23.125 26.056,22.718 26.121,22.309 C26.727,18.541 25.761,15.919 24.471,14.155 L24.471,14.155 Z M13.65,21.29 C15.259,18.763 13.576,14.325 13.559,14.28 C13.441,13.973 13.481,13.626 13.667,13.354 C13.854,13.082 14.161,12.919 14.491,12.919 C16.242,12.919 17.739,14.274 18.741,15.512 C19.27,11.523 16.864,9.428 16.744,9.328 C16.4,9.036 16.291,8.546 16.484,8.137 C16.676,7.728 17.114,7.491 17.561,7.576 C19.035,7.837 20.334,8.398 21.411,9.209 C22.366,9.636 27.137,12.048 28.125,17.909 C28.153,17.733 28.176,17.549 28.197,17.359 C28.231,17.026 28.43,16.732 28.727,16.577 C29.025,16.421 29.379,16.425 29.671,16.585 C29.858,16.688 34.204,19.18 32.055,27.502 C30.38,33.99 21.875,34.729 21.514,34.757 L21.513,34.747 C21.491,34.749 21.472,34.76 21.45,34.76 C21.338,34.76 21.224,34.741 21.115,34.701 C19.061,33.967 17.268,33.071 15.785,32.038 C12.471,29.728 11.421,25.191 13.395,21.711 C13.476,21.57 13.56,21.43 13.65,21.29 L13.65,21.29 Z M5.49,33.95 L7.111,32.777 C5.03,29.902 3.86,26.538 3.676,23 L6,23 L6,21 L3.679,21 C3.871,17.483 5.04,14.14 7.111,11.281 L5.49,10.108 C3.172,13.311 1.873,17.059 1.679,21 L0,21 L0,23 L1.676,23 C1.862,26.962 3.16,30.731 5.49,33.95 L5.49,33.95 Z M32.747,36.918 C29.88,38.993 26.528,40.162 23,40.351 L23,38 L21,38 L21,40.351 C17.472,40.163 14.118,38.994 11.25,36.918 L10.078,38.539 C13.289,40.862 17.049,42.161 21,42.351 L21,44 L23,44 L23,42.351 C26.951,42.16 30.709,40.862 33.919,38.539 L32.747,36.918 Z M11.25,7.14 C14.118,5.064 17.472,3.896 21,3.708 L21,6 L23,6 L23,3.708 C26.528,3.896 29.88,5.065 32.747,7.14 L33.919,5.52 C30.709,3.196 26.951,1.897 23,1.708 L23,0 L21,0 L21,1.708 C17.048,1.897 13.289,3.196 10.078,5.52 L11.25,7.14 Z M42.32,21 C42.125,17.059 40.826,13.311 38.509,10.108 L36.888,11.281 C38.958,14.14 40.127,17.483 40.32,21 L38,21 L38,23 L40.323,23 C40.139,26.538 38.969,29.902 36.888,32.777 L38.509,33.95 C40.838,30.731 42.137,26.962 42.323,23 L44,23 L44,21 L42.32,21 Z" id="AWS-WAF_Icon_48_Squid"></path>
        </g>
    </g>""",
    
    "aws_cloudfront_distribution": """<g id="Icon-Architecture/48/Arch_Amazon-CloudFront_48" stroke="none" stroke-width="1" fill="none" fill-rule="evenodd">
        <g id="Icon-Architecture-BG/48/Networking-Content-Delivery" fill="#8C4FFF">
            <rect id="Rectangle" x="0" y="0" width="64" height="64" rx="8"></rect>
        </g>
        <path d="M41.5,43.5 C40.397,43.5 39.5,42.603 39.5,41.5 C39.5,40.397 40.397,39.5 41.5,39.5 C42.603,39.5 43.5,40.397 43.5,41.5 C43.5,42.603 42.603,43.5 41.5,43.5 L41.5,43.5 Z M41.5,37.5 C39.294,37.5 37.5,39.294 37.5,41.5 C37.5,43.706 39.294,45.5 41.5,45.5 C43.706,45.5 45.5,43.706 45.5,41.5 C45.5,39.294 43.706,37.5 41.5,37.5 L41.5,37.5 Z M22.5,32.5 C21.397,32.5 20.5,31.603 20.5,30.5 C20.5,29.397 21.397,28.5 22.5,28.5 C23.603,28.5 24.5,29.397 24.5,30.5 C24.5,31.603 23.603,32.5 22.5,32.5 L22.5,32.5 Z M22.5,26.5 C20.294,26.5 18.5,28.294 18.5,30.5 C18.5,32.706 20.294,34.5 22.5,34.5 C24.706,34.5 26.5,32.706 26.5,30.5 C26.5,28.294 24.706,26.5 22.5,26.5 L22.5,26.5 Z M45.389,47.124 C45.168,46.607 44.936,46.094 44.685,45.591 L42.896,46.486 C43.17,47.035 43.42,47.599 43.656,48.165 C42.82,48.762 41.943,49.288 41.028,49.74 C41.384,48.865 41.694,47.975 41.974,47.012 L40.054,46.454 C39.564,48.134 38.985,49.581 38.184,51.133 C36.357,51.698 34.452,52 32.5,52 C29.465,52 26.567,51.314 23.871,49.976 C22.503,46.615 21.838,43.534 21.838,40.559 C21.838,39.267 22.063,38.196 22.322,36.956 C22.386,36.652 22.45,36.343 22.514,36.024 L20.551,35.638 C20.49,35.949 20.427,36.25 20.365,36.545 C20.094,37.838 19.838,39.06 19.838,40.559 C19.838,43.074 20.274,45.644 21.154,48.354 C16.072,44.724 13,38.854 13,32.5 C13,32.389 13.01,32.273 13.012,32.161 C14.642,31.799 16.123,31.614 17.854,31.571 L17.804,29.572 C16.169,29.612 14.694,29.779 13.163,30.084 C14.081,22.683 19.212,16.394 26.323,14.019 C27.873,14.818 29.02,15.524 30.135,16.37 L31.344,14.776 C30.646,14.248 29.934,13.771 29.146,13.299 C30.244,13.108 31.363,13 32.5,13 C35.032,13 37.532,13.494 39.849,14.439 C39.342,14.593 38.82,14.763 38.243,14.971 L38.923,16.852 C40.316,16.349 41.408,16.04 42.571,15.821 C48.399,19.341 52,25.667 52,32.5 C52,38.156 49.605,43.416 45.389,47.124 L45.389,47.124 Z M43.008,13.749 C39.826,11.95 36.192,11 32.5,11 C30.392,11 28.324,11.301 26.357,11.895 C17.723,14.464 11.568,22.23 11.045,31.196 C11.01,31.625 11,32.062 11,32.5 C11,40.444 15.352,47.707 22.354,51.455 C25.459,53.12 28.968,54 32.5,54 C34.892,54 37.229,53.61 39.437,52.843 C41.684,52.086 43.773,50.963 45.646,49.507 C50.955,45.399 54,39.2 54,32.5 C54,24.732 49.787,17.546 43.008,13.749 L43.008,13.749 Z M38.384,37.411 L37.003,38.858 C34.022,36.015 31.047,34.146 27.637,32.975 L28.287,31.083 C31.979,32.351 35.188,34.362 38.384,37.411 L38.384,37.411 Z M38.444,22.364 C41.282,26.692 42.88,31.444 43.193,36.488 L41.197,36.612 C40.905,31.919 39.417,27.495 36.772,23.46 L38.444,22.364 Z M26.451,26.797 L24.773,25.708 C26.316,23.332 27.639,21.758 29.336,20.278 L30.65,21.786 C29.103,23.135 27.886,24.587 26.451,26.797 L26.451,26.797 Z M34.5,16.5 C35.603,16.5 36.5,17.397 36.5,18.5 C36.5,19.603 35.603,20.5 34.5,20.5 C33.397,20.5 32.5,19.603 32.5,18.5 C32.5,17.397 33.397,16.5 34.5,16.5 L34.5,16.5 Z M34.5,22.5 C36.706,22.5 38.5,20.706 38.5,18.5 C38.5,16.294 36.706,14.5 34.5,14.5 C32.294,14.5 30.5,16.294 30.5,18.5 C30.5,20.706 32.294,22.5 34.5,22.5 L34.5,22.5 Z" id="Amazon-CloudFront_Icon_48_Squid" fill="#FFFFFF"></path>
    </g>""",
    
    "aws_s3_bucket": """<g id="Icon-Architecture/48/Arch_Amazon-Simple-Storage-Service_48" stroke="none" stroke-width="1" fill="none" fill-rule="evenodd">
        <g id="Icon-Architecture-BG/48/Storage" fill="#7AA116">
            <rect id="Rectangle" x="0" y="0" width="64" height="64" rx="8"></rect>
        </g>
        <g id="Icon-Service/48/Amazon-Simple-Storage-Service_48" transform="translate(11, 10)" fill="#FFFFFF">
            <path d="M36.759,23.948 L36.993,22.131 C39.166,23.385 39.842,24.121 40.037,24.424 C39.713,24.485 38.832,24.509 36.759,23.948 L36.759,23.948 Z M19.5,11 C9.125,11 2.382,8.488 2,6.696 L2,6.511 C2.349,5.392 8.14,2 19.5,2 C30.84,2 36.632,5.381 37,6.505 L37,6.616 C36.724,8.446 29.961,11 19.5,11 L19.5,11 Z M34.818,23.362 C30.053,21.797 23.912,18.979 21.594,17.888 C21.535,16.786 20.628,15.906 19.512,15.906 C18.358,15.906 17.418,16.845 17.418,18 C17.418,19.154 18.358,20.094 19.512,20.094 C19.969,20.094 20.389,19.942 20.733,19.693 C23.132,20.822 29.619,23.798 34.558,25.38 L32.837,38.724 C32.583,40.352 27.919,42 19.497,42 C11.072,42 6.405,40.352 6.155,38.751 L2.435,9.814 C5.945,11.915 12.749,13 19.5,13 C26.25,13 33.054,11.915 36.565,9.815 L34.818,23.362 Z M39,6.5 C39,3.431 30.661,0 19.5,0 C8.339,0 0,3.431 0,6.5 L0,7.043 L4.174,39.033 C4.875,43.516 15.123,44 19.497,44 C23.869,44 34.113,43.516 34.818,39.007 L36.501,25.947 C37.778,26.279 38.812,26.456 39.616,26.455 C40.606,26.455 41.273,26.203 41.697,25.697 C42.047,25.281 42.185,24.756 42.085,24.221 C41.857,23 40.403,21.712 37.37,20.044 L37.27,19.989 L39,7.044 L39,6.5 Z" id="Amazon-Simple-Storage-Service-Icon_48_Squid"></path>
        </g>
    </g>""",
    
    "aws_acm_certificate": """<g id="Icon-Architecture/48/Arch_AWS-Certificate-Manager_48" stroke="none" stroke-width="1" fill="none" fill-rule="evenodd">
        <g id="Icon-Architecture-BG/48/Security-Identity-Compliance" fill="#DD344C">
            <rect id="Rectangle" x="0" y="0" width="64" height="64" rx="8"></rect>
        </g>
        <path d="M28.722,30.981 C28.946,31.214 29.042,31.541 28.983,31.858 L28.394,34.998 L31.486,33.143 C31.644,33.047 31.823,33 32,33 C32.178,33 32.357,33.047 32.515,33.143 L35.608,34.998 L35.018,31.852 C34.958,31.535 35.055,31.209 35.279,30.976 L37.94,28.197 L34.355,27.665 C34.041,27.618 33.769,27.426 33.619,27.147 L31.992,24.104 L30.325,27.158 C30.175,27.432 29.906,27.621 29.596,27.668 L26.057,28.204 L28.722,30.981 Z M26.018,36.815 L26.922,31.995 L23.279,28.197 C23.02,27.927 22.933,27.536 23.054,27.183 C23.174,26.829 23.481,26.572 23.851,26.516 L28.806,25.764 L31.122,21.521 C31.298,21.2 31.635,21 32,21 L32.004,21 C32.371,21.002 32.708,21.205 32.882,21.528 L35.146,25.76 L40.147,26.503 C40.517,26.558 40.826,26.814 40.947,27.168 C41.068,27.523 40.981,27.914 40.722,28.184 L37.077,31.988 L37.983,36.816 C38.056,37.203 37.895,37.596 37.572,37.821 C37.249,38.045 36.825,38.06 36.486,37.857 L32,35.166 L27.515,37.857 C27.356,37.953 27.178,38 27,38 C26.8,38 26.6,37.94 26.429,37.821 C26.106,37.596 25.945,37.203 26.018,36.815 L26.018,36.815 Z M12,17.017 L51.997,17.017 L51.997,13 L12,13 L12,17.017 Z M54,52 C54,52.265 53.895,52.52 53.707,52.707 C53.52,52.895 53.266,53 53,53 L48,53 L48,51 L52,51 L51.998,19.017 L12,19.017 L12,51 L41,51 L41,53 L11,53 C10.448,53 10,52.552 10,52 L10,12 C10,11.448 10.448,11 11,11 L52.997,11 C53.55,11 53.997,11.448 53.997,12 L54,52 Z M19,47 L24,47 L24,45 L19,45 L19,47 Z M27,47 L38,47 L38,45 L27,45 L27,47 Z M19,42.997 L24,42.997 L24,40.997 L19,40.997 L19,42.997 Z M27,43 L45,43 L45,41 L27,41 L27,43 Z" id="AWS-Certificate-Manager_Icon_48_Squid" fill="#FFFFFF"></path>
    </g>""",
    
    "aws_api_gateway_rest_api": """<g id="Icon-Architecture/48/Arch_Amazon-API-Gateway_48" stroke="none" stroke-width="1" fill="none" fill-rule="evenodd">
        <g id="Icon-Architecture-BG/48/App-Integration" fill="#E7157B">
            <rect id="Rectangle" x="0" y="0" width="64" height="64" rx="8"></rect>
        </g>
        <path d="M36,43.996 L36,20.007 L28,20.007 L28,43.996 L36,43.996 Z M38,18.007 L38,45.996 L26,45.996 L26,18.007 L38,18.007 Z M46.293,30.588 L42,34.879 L42,29.124 L46.293,33.415 L46.293,30.588 Z M52.707,32.001 L40,19.296 L40,28.004 L33,28.004 L33,21.007 L31,21.007 L31,28.004 L24,28.004 L24,19.296 L11.293,32.001 L24,44.707 L24,36.004 L31,36.004 L31,43.003 L33,43.003 L33,36.004 L40,36.004 L40,44.707 L52.707,32.001 Z M22,34.879 L17.707,30.588 L17.707,33.415 L22,29.124 L22,34.879 Z M54.707,32.001 L41.414,45.293 C41.039,45.668 40.531,45.879 40,45.879 L40,46.996 L38,46.996 L38,47.996 L26,47.996 L26,46.996 L24,46.996 L24,45.879 C23.469,45.879 22.961,45.668 22.586,45.293 L9.293,32.001 C8.902,31.611 8.902,30.977 9.293,30.588 L22.586,17.296 C22.961,16.921 23.469,16.71 24,16.71 L24,16.007 L26,16.007 L26,16.007 L38,16.007 L38,16.007 L40,16.007 L40,16.71 C40.531,16.71 41.039,16.921 41.414,17.296 L54.707,30.588 C55.098,30.977 55.098,31.611 54.707,32.001 Z" id="Amazon-API-Gateway_Icon_48_Squid" fill="#FFFFFF"></path>
    </g>""",
    
    "aws_sqs_queue": """<g id="Icon-Architecture/48/Arch_Amazon-Simple-Queue-Service_48" stroke="none" stroke-width="1" fill="none" fill-rule="evenodd">
        <g id="Icon-Architecture-BG/48/App-Integration" fill="#E7157B">
            <rect id="Rectangle" x="0" y="0" width="64" height="64" rx="8"></rect>
        </g>
        <path d="M17,35 L14,35 L14,29 L17,29 L17,35 Z M13,37 L18,37 C18.552,37 19,36.553 19,36 L19,28 C19,27.447 18.552,27 18,27 L13,27 C12.448,27 12,27.447 12,28 L12,36 C12,36.553 12.448,37 13,37 L13,37 Z M27,35 L24,35 L24,29 L27,29 L27,35 Z M23,37 L28,37 C28.552,37 29,36.553 29,36 L29,28 C29,27.447 28.552,27 28,27 L23,27 C22.448,27 22,27.447 22,28 L22,36 C22,36.553 22.448,37 23,37 L23,37 Z M37,35 L34,35 L34,29 L37,29 L37,35 Z M33,37 L38,37 C38.552,37 39,36.553 39,36 L39,28 C39,27.447 38.552,27 38,27 L33,27 C32.448,27 32,27.447 32,28 L32,36 C32,36.553 32.448,37 33,37 L33,37 Z M47,35 L44,35 L44,29 L47,29 L47,35 Z M43,37 L48,37 C48.552,37 49,36.553 49,36 L49,28 C49,27.447 48.552,27 48,27 L43,27 C42.448,27 42,27.447 42,28 L42,36 C42,36.553 42.448,37 43,37 L43,37 Z M52,32 C52,33.654 50.654,35 49,35 L49,37 C51.757,37 54,34.757 54,32 C54,29.243 51.757,27 49,27 L49,29 C50.654,29 52,30.346 52,32 L52,32 Z M11,27 L11,29 C9.346,29 8,30.346 8,32 C8,33.654 9.346,35 11,35 L11,37 C8.243,37 6,34.757 6,32 C6,29.243 8.243,27 11,27 L11,27 Z" id="Amazon-Simple-Queue-Service_Icon_48_Squid" fill="#FFFFFF"></path>
    </g>""",
    
    "aws_sns_topic": """<g id="Icon-Architecture/48/Arch_Amazon-Simple-Notification-Service_48" stroke="none" stroke-width="1" fill="none" fill-rule="evenodd">
        <g id="Icon-Architecture-BG/48/App-Integration" fill="#E7157B">
            <rect id="Rectangle" x="0" y="0" width="64" height="64" rx="8"></rect>
        </g>
        <path d="M44,38 C42.897,38 42,37.103 42,36 C42,34.897 42.897,34 44,34 C45.103,34 46,34.897 46,36 C46,37.103 45.103,38 44,38 M44,32 C41.791,32 40,33.791 40,36 C40,38.209 41.791,40 44,40 C46.209,40 48,38.209 48,36 C48,33.791 46.209,32 44,32 M21,30 C19.897,30 19,29.103 19,28 C19,26.897 19.897,26 21,26 C22.103,26 23,26.897 23,28 C23,29.103 22.103,30 21,30 M21,24 C18.791,24 17,25.791 17,28 C17,30.209 18.791,32 21,32 C23.209,32 25,30.209 25,28 C25,25.791 23.209,24 21,24 M44,22 C42.897,22 42,21.103 42,20 C42,18.897 42.897,18 44,18 C45.103,18 46,18.897 46,20 C46,21.103 45.103,22 44,22 M44,16 C41.791,16 40,17.791 40,20 C40,22.209 41.791,24 44,24 C46.209,24 48,22.209 48,20 C48,17.791 46.209,16 44,16 M32,46 C30.897,46 30,45.103 30,44 C30,42.897 30.897,42 32,42 C33.103,42 34,42.897 34,44 C34,45.103 33.103,46 32,46 M32,40 C29.791,40 28,41.791 28,44 C28,46.209 29.791,48 32,48 C34.209,48 36,46.209 36,44 C36,41.791 34.209,40 32,40 M33,36 L40,36 L40,34 L33,34 C32.448,34 32,34.448 32,35 C32,35.552 32.448,36 33,36 M25,29 L33,29 C33.552,29 34,28.552 34,28 C34,27.448 33.552,27 33,27 L25,27 C24.448,27 24,27.448 24,28 C24,28.552 24.448,29 25,29 M33,20 L40,20 L40,18 L33,18 C32.448,18 32,18.448 32,19 C32,19.552 32.448,20 33,20 M32,37 C32.552,37 33,37.448 33,38 L33,41 L31,41 L31,38 C31,37.448 31.448,37 32,37" id="Amazon-Simple-Notification-Service_Icon_48_Squid" fill="#FFFFFF"></path>
    </g>""",
}

# Alias for Lambda URL (same icon as Lambda)
EMBEDDED_ICONS["aws_lambda_function_url"] = EMBEDDED_ICONS["aws_lambda_function"]
EMBEDDED_ICONS["aws_apigatewayv2_api"] = EMBEDDED_ICONS["aws_api_gateway_rest_api"]
EMBEDDED_ICONS["aws_lb"] = EMBEDDED_ICONS["aws_api_gateway_rest_api"]  # Use API icon for ALB
EMBEDDED_ICONS["aws_alb"] = EMBEDDED_ICONS["aws_api_gateway_rest_api"]


# =============================================================================
# ICON LOADING
# =============================================================================

def get_icon(resource_type: str, icons_dir: Optional[Path] = None) -> Optional[str]:
    """Get icon SVG content - first check embedded, then external."""
    # First try embedded icons
    if resource_type in EMBEDDED_ICONS:
        return EMBEDDED_ICONS[resource_type]
    
    # Then try external icons directory
    if icons_dir and icons_dir.exists():
        icon_file = ICON_FILES.get(resource_type)
        if icon_file:
            for path in icons_dir.rglob(icon_file):
                try:
                    content = path.read_text()
                    match = re.search(r'<svg[^>]*>(.*)</svg>', content, re.DOTALL)
                    if match:
                        return match.group(1)
                except:
                    pass
    
    return None


# =============================================================================
# SVG GENERATION
# =============================================================================

def esc(s: str) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def trunc(s: str, max_len: int = 12) -> str:
    return s if len(s) <= max_len else s[:max_len-1] + "…"


def get_color(category: str) -> str:
    return COLORS.get(category, COLORS["default"])


def svg_defs() -> str:
    return f'''  <defs>
    <marker id="arrow" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
      <path d="M0,0 L0,6 L8,3 z" fill="{COLORS['arrow']}"/>
    </marker>
    <marker id="arrow-mid" markerWidth="10" markerHeight="8" refX="5" refY="4" orient="auto">
      <path d="M0,0 L10,4 L0,8 z" fill="{COLORS['arrow']}"/>
    </marker>
    <filter id="shadow" x="-20%" y="-20%" width="140%" height="140%">
      <feDropShadow dx="0" dy="2" stdDeviation="3" flood-opacity="0.1"/>
    </filter>
  </defs>'''


def svg_module(b: dict) -> str:
    x, y, w, h = b["x"], b["y"], b["w"], b["h"]
    return f'''  <g class="module">
    <rect x="{x}" y="{y}" width="{w}" height="{h}" fill="{COLORS['module_bg']}" stroke="{COLORS['module_border']}" rx="8"/>
    <rect x="{x}" y="{y}" width="{w}" height="{MODULE_HDR}" fill="{COLORS['module_hdr']}" rx="8"/>
    <rect x="{x}" y="{y + MODULE_HDR - 8}" width="{w}" height="8" fill="{COLORS['module_hdr']}"/>
    <text x="{x + 16}" y="{y + 21}" font-size="13" font-weight="600" fill="{COLORS['text_inv']}">{esc(b['label'])}</text>
  </g>'''


def svg_node(node: Node, pos: Position, icon_svg: Optional[str] = None) -> str:
    x, y = pos.x, pos.y
    info = SERVICE_INFO.get(node.resource_type, (node.resource_type, "?", "default"))
    label, abbrev, category = info
    color = get_color(category)
    name = trunc(node.name)
    
    icon_x = x + (NODE_W - ICON_SIZE) // 2
    icon_y = y + 12
    
    if icon_svg:
        scale = ICON_SIZE / 64
        icon_content = f'''    <g transform="translate({icon_x},{icon_y}) scale({scale})">
{icon_svg}
    </g>'''
    else:
        icon_content = f'''    <rect x="{icon_x}" y="{icon_y}" width="{ICON_SIZE}" height="{ICON_SIZE}" rx="6" fill="{color}"/>
    <text x="{icon_x + ICON_SIZE//2}" y="{icon_y + 32}" font-size="14" font-weight="600" fill="white" text-anchor="middle">{abbrev}</text>'''
    
    # Only show name if it's different from module name and adds info
    # Skip generic names that match module context
    show_name = True
    if node.module:
        # Normalize for comparison
        mod_lower = node.module.lower().replace("_", "").replace("-", "")
        name_lower = node.name.lower().replace("_", "").replace("-", "")
        # Hide if name is essentially the module name
        if name_lower in mod_lower or mod_lower in name_lower:
            show_name = False
    
    name_line = f'    <text x="{x + NODE_W//2}" y="{y + NODE_H - 10}" font-size="11" fill="{COLORS["text"]}" text-anchor="middle">{esc(name)}</text>' if show_name else ''
    
    return f'''  <g class="node">
    <rect x="{x}" y="{y}" width="{NODE_W}" height="{NODE_H}" fill="{COLORS['node_bg']}" stroke="{COLORS['node_border']}" rx="6" filter="url(#shadow)"/>
{icon_content}
    <text x="{x + NODE_W//2}" y="{y + NODE_H - 24}" font-size="9" fill="{COLORS['text2']}" text-anchor="middle">{esc(label)}</text>
{name_line}
  </g>'''


def svg_arrow(from_pos: Position, to_pos: Position) -> str:
    """Draw arrow between two nodes."""
    x1 = from_pos.right + ARROW_GAP
    y1 = from_pos.cy
    x2 = to_pos.left - ARROW_GAP
    y2 = to_pos.cy
    
    # Same row - straight line
    if abs(y1 - y2) < GRID * 2:
        return f'  <line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{COLORS["arrow"]}" stroke-width="1.5" marker-end="url(#arrow)"/>'
    
    # Different rows - orthogonal routing
    mid_x = (x1 + x2) // 2
    return f'  <path d="M{x1},{y1} L{mid_x},{y1} L{mid_x},{y2} L{x2},{y2}" fill="none" stroke="{COLORS["arrow"]}" stroke-width="1.5" marker-end="url(#arrow)"/>'


def svg_user_arrow(user_pos: Position, target_pos: Position, offset: int = 0) -> str:
    """Draw curved line from user to entry point (no arrowhead)."""
    x1 = user_pos.right
    y1 = user_pos.cy + offset
    x2 = target_pos.left - ARROW_GAP
    y2 = target_pos.cy
    
    # Bezier curve, no marker
    ctrl_x = x1 + 24
    return f'  <path d="M{x1},{y1} C{ctrl_x},{y1} {ctrl_x},{y2} {x2},{y2}" fill="none" stroke="{COLORS["arrow"]}" stroke-width="1.5"/>'


def svg_cross_module_arrow(from_pos: Position, to_pos: Position) -> str:
    """Draw dashed curved line for cross-module API calls.
    
    Uses dashed style to indicate bidirectional request/response flow.
    No arrowheads - the connection itself shows the relationship.
    """
    x1 = from_pos.cx
    y1 = from_pos.y + from_pos.h + ARROW_GAP
    x2 = to_pos.cx
    y2 = to_pos.y - ARROW_GAP
    
    # If caller is below callee, flip the connection points
    if y1 > y2:
        y1 = from_pos.y - ARROW_GAP
        y2 = to_pos.y + to_pos.h + ARROW_GAP
    
    mid_y = (y1 + y2) // 2
    
    return f'  <path d="M{x1},{y1} C{x1},{mid_y} {x2},{mid_y} {x2},{y2}" fill="none" stroke="{COLORS["arrow"]}" stroke-width="1.5" stroke-dasharray="4,3"/>'


def svg_user(pos: Position) -> str:
    return f'''  <g class="user" transform="translate({pos.x},{pos.y})">
    <circle cx="24" cy="12" r="9" fill="none" stroke="{COLORS['user']}" stroke-width="2"/>
    <path d="M8,38 Q8,24 24,24 Q40,24 40,38" fill="none" stroke="{COLORS['user']}" stroke-width="2"/>
    <text x="24" y="54" font-size="11" fill="{COLORS['text']}" text-anchor="middle">Users</text>
  </g>'''


def generate_svg(nodes: Dict[str, Node], edges: List[Edge], 
                 cross_edges: List[Edge] = None,
                 icons_dir: Optional[Path] = None,
                 title: str = None, show_user: bool = True) -> str:
    """Generate complete SVG."""
    
    L = layout(nodes, title)
    positions = L["positions"]
    w, h = int(L["width"]), int(L["height"])
    
    # Load icons (embedded first, then external)
    icon_cache = {}
    for node in nodes.values():
        if node.resource_type not in icon_cache:
            icon_cache[node.resource_type] = get_icon(node.resource_type, icons_dir)
    
    parts = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}"',
        f'     style="font-family: -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif;">',
        svg_defs(),
        f'  <rect width="100%" height="100%" fill="{COLORS["bg"]}"/>',
    ]
    
    # Title
    if title:
        parts.append(f'  <text x="{CANVAS_PAD}" y="{L["title_y"]}" font-size="18" font-weight="600" fill="{COLORS["text"]}">{esc(title)}</text>')
    
    # Modules
    for b in L["modules"].values():
        parts.append(svg_module(b))
    
    # Nodes
    for node_id, pos in positions.items():
        node = nodes[node_id]
        icon = icon_cache.get(node.resource_type)
        parts.append(svg_node(node, pos, icon))
    
    # Intra-module dependency arrows (solid)
    for edge in edges:
        if edge.from_id in positions and edge.to_id in positions:
            from_pos = positions[edge.from_id]
            to_pos = positions[edge.to_id]
            parts.append(svg_arrow(from_pos, to_pos))
    
    # Cross-module arrows (dashed)
    if cross_edges:
        for edge in cross_edges:
            if edge.from_id in positions and edge.to_id in positions:
                from_pos = positions[edge.from_id]
                to_pos = positions[edge.to_id]
                parts.append(svg_cross_module_arrow(from_pos, to_pos))
    
    # User arrows
    if show_user and L["entry_points"]:
        user_pos = L["user"]
        parts.append(svg_user(user_pos))
        
        entries = L["entry_points"]
        n_entries = len(entries)
        
        for i, (nid, pos) in enumerate(entries):
            offset = (i - n_entries // 2) * 12
            parts.append(svg_user_arrow(user_pos, pos, offset))
    
    parts.append('</svg>')
    return '\n'.join(parts)


# =============================================================================
# CLI
# =============================================================================

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Generate AWS architecture diagram from Terraform graph',
        epilog='Example: terraform graph | python graph2svg.py - arch.svg --title "My Infra"'
    )
    parser.add_argument('input', help='DOT file or - for stdin')
    parser.add_argument('output', help='Output SVG file')
    parser.add_argument('--title', help='Diagram title')
    parser.add_argument('--icons', help='Path to AWS icons directory')
    parser.add_argument('--no-user', action='store_true', help='Hide user icon')
    parser.add_argument('--no-cross', action='store_true', help='Hide cross-module connections')
    
    args = parser.parse_args()
    
    # Read input
    if args.input == '-':
        dot_content = sys.stdin.read()
    else:
        p = Path(args.input)
        if not p.exists():
            print(f"Error: {args.input} not found", file=sys.stderr)
            sys.exit(1)
        dot_content = p.read_text()
    
    # Parse
    nodes, edges = parse_dot(dot_content)
    intra_edges, cross_edges = filter_edges(nodes, edges)
    
    if not nodes:
        print("Warning: No resources found in graph", file=sys.stderr)
    
    # Icons directory
    icons_dir = Path(args.icons) if args.icons else None
    
    # Generate
    svg = generate_svg(
        nodes, 
        intra_edges, 
        cross_edges if not args.no_cross else None,
        icons_dir, 
        args.title, 
        not args.no_user
    )
    Path(args.output).write_text(svg)
    
    # Stats
    modules = set(n.module or "_root" for n in nodes.values())
    flows = set(n.flow for n in nodes.values())
    print(f"✓ {args.output}", file=sys.stderr)
    print(f"  {len(nodes)} resources, {len(intra_edges)} intra-module + {len(cross_edges)} cross-module connections", file=sys.stderr)
    print(f"  Flow paths: {', '.join(sorted(flows))}", file=sys.stderr)


if __name__ == "__main__":
    main()