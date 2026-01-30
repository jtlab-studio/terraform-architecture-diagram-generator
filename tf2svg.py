#!/usr/bin/env python3
"""
tf2svg - Professional AWS Architecture Diagram Generator

Design Principles Applied:
1. 8px grid system for consistent spacing
2. Grid-based arrow routing to prevent overlaps
3. Clear visual hierarchy (entry → process → data → support)
4. Proper typography with readable labels
5. AWS-compliant color palette

Usage:
    terraform show -json | python tf2svg.py - output.svg
    python tf2svg.py tfstate.json output.svg [--title "text"] [--no-user]
"""

import json
import sys
import re
from pathlib import Path
from collections import defaultdict
from typing import Optional, List, Tuple, Set, Dict

# =============================================================================
# DESIGN SYSTEM (8px grid)
# =============================================================================

GRID = 8  # Base unit

# Node dimensions
ICON_SIZE = 48
NODE_W = 14 * GRID      # 112px
NODE_H = 13 * GRID      # 104px (increased for better label spacing)
NODE_RADIUS = GRID

# Spacing
H_GAP = 5 * GRID        # 40px horizontal gap between nodes
V_GAP = 10 * GRID       # 80px vertical gap between modules
MODULE_PAD = 3 * GRID   # 24px padding inside module
MODULE_HDR = 4 * GRID   # 32px header height
CANVAS_PAD = 8 * GRID   # 64px canvas edge padding
USER_W = 10 * GRID      # 80px user area width

# Arrow routing
ROUTE_MARGIN = 2 * GRID # 16px clearance from nodes
ROUTE_CHANNEL = 3 * GRID # 24px between parallel arrows

# Colors (AWS palette)
C = {
    "bg": "#ffffff",
    "module_bg": "#f7f8f8",
    "module_border": "#d5dbdb",
    "module_hdr": "#232f3e",
    "node_bg": "#ffffff",
    "node_border": "#d5dbdb",
    "text": "#232f3e",
    "text2": "#545b64",
    "text_inv": "#ffffff",
    "arrow": "#545b64",
    "user": "#232f3e",
    # Service colors
    "compute": "#ED7100",
    "database": "#C925D1",
    "storage": "#7AA116",
    "network": "#8C4FFF",
    "security": "#DD344C",
    "integration": "#E7157B",
}

# =============================================================================
# RESOURCE CONFIGURATION
# =============================================================================

SHOW_RESOURCES = {
    "aws_lambda_function", "aws_lambda_function_url",
    "aws_instance", "aws_ecs_service", "aws_ecs_cluster", "aws_eks_cluster",
    "aws_db_instance", "aws_rds_cluster", "aws_dynamodb_table",
    "aws_elasticache_cluster", "aws_redshift_cluster",
    "aws_s3_bucket", "aws_efs_file_system",
    "aws_lb", "aws_alb", "aws_cloudfront_distribution",
    "aws_route53_zone", "aws_api_gateway_rest_api", "aws_apigatewayv2_api",
    "aws_acm_certificate", "aws_wafv2_web_acl", "aws_cognito_user_pool",
    "aws_sqs_queue", "aws_sns_topic", "aws_sfn_state_machine",
    "aws_eventbridge_rule", "aws_kinesis_stream",
    "aws_codepipeline", "aws_ecr_repository",
}

# Tier ordering (left to right flow)
TIERS = {
    "aws_route53_zone": 0,
    "aws_wafv2_web_acl": 1,
    "aws_cloudfront_distribution": 2,
    "aws_api_gateway_rest_api": 2,
    "aws_apigatewayv2_api": 2,
    "aws_lb": 2, "aws_alb": 2,
    "aws_lambda_function_url": 2,
    "aws_lambda_function": 3,
    "aws_ecs_service": 3, "aws_instance": 3,
    "aws_s3_bucket": 4, "aws_sqs_queue": 4, "aws_sns_topic": 4,
    "aws_dynamodb_table": 5, "aws_db_instance": 5,
    "aws_rds_cluster": 5, "aws_elasticache_cluster": 5,
    "aws_acm_certificate": 6, "aws_cognito_user_pool": 6,
}

ENTRY_POINTS = {
    "aws_route53_zone",
    # "aws_cloudfront_distribution",  # Users enter via DNS, not direct
    "aws_api_gateway_rest_api",
    "aws_apigatewayv2_api",
    "aws_lb", "aws_alb",
    "aws_lambda_function_url",  # Direct function URL access
}

# Dependency patterns for arrow inference
# Note: Route53 -> CloudFront is NOT included because DNS resolution
# is not a data flow - users hit Route53, get DNS response, then 
# their browser connects to CloudFront directly
DEP_PATTERNS = [
    ("aws_lambda_function_url", "aws_lambda_function"),
    ("aws_lambda_function", "aws_dynamodb_table"),
    ("aws_lambda_function", "aws_s3_bucket"),
    ("aws_lambda_function", "aws_rds_cluster"),
    ("aws_lambda_function", "aws_sqs_queue"),
    ("aws_cloudfront_distribution", "aws_s3_bucket"),
    ("aws_cloudfront_distribution", "aws_lambda_function_url"),
    # ("aws_route53_zone", "aws_cloudfront_distribution"),  # DNS, not data flow
    # ("aws_route53_zone", "aws_lb"),  # DNS, not data flow
    ("aws_api_gateway_rest_api", "aws_lambda_function"),
    ("aws_lb", "aws_ecs_service"),
    ("aws_ecs_service", "aws_dynamodb_table"),
    ("aws_sqs_queue", "aws_lambda_function"),
]

SERVICE_LABELS = {
    "aws_lambda_function": "Lambda",
    "aws_lambda_function_url": "Lambda URL",
    "aws_dynamodb_table": "DynamoDB",
    "aws_s3_bucket": "S3",
    "aws_cloudfront_distribution": "CloudFront",
    "aws_route53_zone": "Route 53",
    "aws_api_gateway_rest_api": "API Gateway",
    "aws_apigatewayv2_api": "API Gateway",
    "aws_lb": "ALB", "aws_alb": "ALB",
    "aws_acm_certificate": "ACM",
    "aws_wafv2_web_acl": "WAF",
    "aws_cognito_user_pool": "Cognito",
    "aws_sqs_queue": "SQS",
    "aws_sns_topic": "SNS",
    "aws_ecs_service": "ECS",
    "aws_instance": "EC2",
    "aws_db_instance": "RDS",
    "aws_rds_cluster": "Aurora",
    "aws_elasticache_cluster": "ElastiCache",
}


# =============================================================================
# GRID-BASED ROUTING SYSTEM
# =============================================================================

class RoutingGrid:
    """
    Manages arrow routing to prevent overlaps.
    Uses a virtual grid where nodes block cells.
    Arrows route through free channels between/around nodes.
    """
    
    def __init__(self, width: int, height: int, cell_size: int = GRID * 2):
        self.cell = cell_size
        self.cols = width // cell_size + 1
        self.rows = height // cell_size + 1
        # Blocked cells (occupied by nodes)
        self.blocked: Set[Tuple[int, int]] = set()
        # Track used routing channels to avoid overlapping arrows
        self.used_h: Dict[int, Set[int]] = defaultdict(set)  # y -> set of x ranges
        self.used_v: Dict[int, Set[int]] = defaultdict(set)  # x -> set of y ranges
    
    def to_grid(self, x: int, y: int) -> Tuple[int, int]:
        return x // self.cell, y // self.cell
    
    def block_rect(self, x: int, y: int, w: int, h: int, margin: int = ROUTE_MARGIN):
        """Mark rectangle as blocked with margin."""
        gx1, gy1 = self.to_grid(x - margin, y - margin)
        gx2, gy2 = self.to_grid(x + w + margin, y + h + margin)
        for gx in range(max(0, gx1), min(self.cols, gx2 + 1)):
            for gy in range(max(0, gy1), min(self.rows, gy2 + 1)):
                self.blocked.add((gx, gy))
    
    def is_clear_h(self, y: int, x1: int, x2: int) -> bool:
        """Check if horizontal path at y from x1 to x2 is clear."""
        gy = y // self.cell
        xmin, xmax = min(x1, x2), max(x1, x2)
        for gx in range(xmin // self.cell, xmax // self.cell + 1):
            if (gx, gy) in self.blocked:
                return False
            # Also check row above and below for margin
            if (gx, gy - 1) in self.blocked or (gx, gy + 1) in self.blocked:
                return False
        return True
    
    def is_clear_v(self, x: int, y1: int, y2: int) -> bool:
        """Check if vertical path is clear."""
        gx = x // self.cell
        ymin, ymax = min(y1, y2), max(y1, y2)
        for gy in range(ymin // self.cell, ymax // self.cell + 1):
            if (gx, gy) in self.blocked:
                return False
        return True
    
    def find_h_channel(self, y1: int, y2: int, x1: int, x2: int) -> int:
        """Find clear horizontal routing channel between y1 and y2."""
        ymin, ymax = min(y1, y2), max(y1, y2)
        # Try positions between the two y values
        for offset in range(0, (ymax - ymin) // 2 + GRID * 8, GRID):
            for y in [ymin + offset, ymax - offset]:
                if ymin - GRID * 2 <= y <= ymax + GRID * 2:
                    if self.is_clear_h(y, x1, x2):
                        return y
        return (y1 + y2) // 2  # Fallback
    
    def route(self, x1: int, y1: int, x2: int, y2: int) -> List[Tuple[int, int]]:
        """
        Route arrow from (x1,y1) to (x2,y2) avoiding blocked areas.
        Returns waypoints for orthogonal path.
        """
        points = [(x1, y1)]
        
        # Same row - check if direct path is clear
        if abs(y1 - y2) <= GRID:
            if self.is_clear_h(y1, min(x1, x2), max(x1, x2)):
                points.append((x2, y2))
                return points
        
        # Check if there are obstacles between source and target
        has_obstacle = False
        for gx in range(x1 // self.cell, x2 // self.cell + 1):
            gy = y1 // self.cell
            if (gx, gy) in self.blocked:
                # Check if this isn't our source/target node
                if gx > (x1 + NODE_W) // self.cell and gx < (x2 - NODE_W) // self.cell:
                    has_obstacle = True
                    break
        
        if not has_obstacle and abs(y1 - y2) <= GRID:
            # Direct horizontal if no obstacle
            points.append((x2, y2))
            return points
        
        # Need orthogonal routing
        mid_x1 = x1 + H_GAP // 3
        
        # Check if simple L-route works
        if self.is_clear_v(mid_x1, y1, y2) and not has_obstacle:
            points.append((mid_x1, y1))
            points.append((mid_x1, y2))
            points.append((x2, y2))
        else:
            # Route above or below the obstacles
            # Find a clear horizontal channel
            y_above = min(y1, y2) - ROUTE_MARGIN * 2
            y_below = max(y1, y2) + ROUTE_MARGIN * 2
            
            # Try routing above first (cleaner visually)
            if y_above > 0 and self.is_clear_h(y_above, x1, x2):
                channel_y = y_above
            elif self.is_clear_h(y_below, x1, x2):
                channel_y = y_below
            else:
                # Find any clear channel
                channel_y = self.find_h_channel(y1, y2, x1, x2)
            
            mid_x2 = x2 - H_GAP // 3
            
            points.append((mid_x1, y1))
            points.append((mid_x1, channel_y))
            points.append((mid_x2, channel_y))
            points.append((mid_x2, y2))
            points.append((x2, y2))
        
        return self._simplify(points)
    
    def _simplify(self, points: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
        """Remove redundant waypoints."""
        if len(points) <= 2:
            return points
        result = [points[0]]
        for i in range(1, len(points) - 1):
            p0, p1, p2 = points[i-1], points[i], points[i+1]
            # Keep point if direction changes
            dx1, dy1 = p1[0] - p0[0], p1[1] - p0[1]
            dx2, dy2 = p2[0] - p1[0], p2[1] - p1[1]
            if (dx1 == 0) != (dx2 == 0) or (dy1 == 0) != (dy2 == 0):
                result.append(p1)
        result.append(points[-1])
        return result


# =============================================================================
# TERRAFORM STATE PARSING
# =============================================================================

def parse_state(data: dict) -> dict:
    """Parse terraform show -json output."""
    resources = []
    
    if "values" in data:
        root = data["values"].get("root_module", {})
    elif "resources" in data:
        # Already simplified format
        return data
    else:
        return {"resources": [], "dependencies": [], "modules": []}
    
    def extract(mod_data: dict, mod_path: str = None):
        for res in mod_data.get("resources", []):
            rtype = res.get("type", "")
            if rtype not in SHOW_RESOURCES:
                continue
            
            vals = res.get("values", {})
            label = (
                vals.get("function_name") or
                vals.get("name") or
                vals.get("bucket") or
                vals.get("domain_name") or
                res.get("name", "unknown")
            )
            
            resources.append({
                "address": res.get("address", f"{rtype}.{res.get('name')}"),
                "type": rtype,
                "name": res.get("name", "unknown"),
                "module": mod_path,
                "label": label,
            })
        
        for child in mod_data.get("child_modules", []):
            child_path = child.get("address", "").replace("module.", "")
            extract(child, child_path or None)
    
    extract(root)
    
    # Infer dependencies
    deps = []
    by_mod_type = defaultdict(list)
    for r in resources:
        by_mod_type[(r.get("module"), r["type"])].append(r)
    
    for src_type, tgt_type in DEP_PATTERNS:
        for (mod, rtype), srcs in by_mod_type.items():
            if rtype != src_type:
                continue
            tgts = by_mod_type.get((mod, tgt_type), [])
            if not tgts and mod:
                tgts = by_mod_type.get((None, tgt_type), [])
            for s in srcs:
                for t in tgts:
                    deps.append({"from": s["address"], "to": t["address"]})
    
    modules = list(set(r["module"] for r in resources if r["module"]))
    return {"resources": resources, "dependencies": deps, "modules": modules}


# =============================================================================
# LAYOUT ENGINE
# =============================================================================

def layout(data: dict, title: str = None) -> dict:
    """Calculate positions for all elements using grid system."""
    resources = [r for r in data.get("resources", []) if r["type"] in SHOW_RESOURCES]
    
    # Group by module
    by_mod = defaultdict(list)
    for r in resources:
        by_mod[r.get("module") or "_root"].append(r)
    
    # Sort by tier within modules
    for mod in by_mod:
        by_mod[mod].sort(key=lambda r: (TIERS.get(r["type"], 4), r["name"]))
    
    # Module order
    mod_order = []
    if "_root" in by_mod:
        mod_order.append("_root")
    mod_order.extend(sorted(m for m in by_mod if m != "_root"))
    
    positions = {}
    mod_bounds = {}
    
    title_h = 6 * GRID if title else 0
    y = CANVAS_PAD + title_h
    max_w = 0
    
    for mod_name in mod_order:
        mod_res = by_mod[mod_name]
        n = len(mod_res)
        
        # Calculate module dimensions
        content_w = n * NODE_W + (n - 1) * H_GAP
        mod_w = content_w + MODULE_PAD * 2
        mod_h = NODE_H + MODULE_PAD * 2 + MODULE_HDR
        mod_x = CANVAS_PAD + USER_W
        
        mod_bounds[mod_name] = {
            "x": mod_x, "y": y, "w": mod_w, "h": mod_h,
            "label": mod_name.replace("_", " ").title() if mod_name != "_root" else "Root"
        }
        
        # Position nodes
        nx = mod_x + MODULE_PAD
        ny = y + MODULE_HDR + MODULE_PAD
        
        for r in mod_res:
            positions[r["address"]] = {
                "x": nx, "y": ny,
                "cx": nx + NODE_W // 2,
                "cy": ny + NODE_H // 2,
                "l": nx, "r": nx + NODE_W,
                "t": ny, "b": ny + NODE_H,
                "res": r,
            }
            nx += NODE_W + H_GAP
        
        max_w = max(max_w, mod_x + mod_w)
        y += mod_h + V_GAP
    
    canvas_h = y - V_GAP + CANVAS_PAD
    user_y = (CANVAS_PAD + title_h + canvas_h - 60) // 2
    
    return {
        "pos": positions,
        "mods": mod_bounds,
        "user": {"x": CANVAS_PAD, "y": user_y},
        "w": max_w + CANVAS_PAD,
        "h": canvas_h,
        "title_y": CANVAS_PAD + 4 * GRID if title else 0,
    }


# =============================================================================
# SVG GENERATION
# =============================================================================

def esc(s: str) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def trunc(s: str, n: int = 12) -> str:
    return s if len(s) <= n else s[:n-1] + "…"


def get_color(rtype: str) -> str:
    rt = rtype.lower()
    if "lambda" in rt or "ec2" in rt or "ecs" in rt or "eks" in rt:
        return C["compute"]
    if "dynamo" in rt or "rds" in rt or "db" in rt or "elasticache" in rt:
        return C["database"]
    if "s3" in rt or "efs" in rt:
        return C["storage"]
    if "route53" in rt or "cloudfront" in rt or "lb" in rt or "gateway" in rt or "api" in rt:
        return C["network"]
    if "acm" in rt or "waf" in rt or "cognito" in rt or "iam" in rt:
        return C["security"]
    if "sqs" in rt or "sns" in rt or "event" in rt or "kinesis" in rt:
        return C["integration"]
    return C["text2"]


def get_abbrev(rtype: str) -> str:
    abbrevs = {
        "aws_lambda_function": "λ",
        "aws_lambda_function_url": "λ",
        "aws_dynamodb_table": "DDB",
        "aws_s3_bucket": "S3",
        "aws_cloudfront_distribution": "CF",
        "aws_route53_zone": "R53",
        "aws_wafv2_web_acl": "WAF",
        "aws_acm_certificate": "ACM",
        "aws_api_gateway_rest_api": "API",
        "aws_lb": "ALB",
        "aws_sqs_queue": "SQS",
        "aws_sns_topic": "SNS",
        "aws_ecs_service": "ECS",
        "aws_instance": "EC2",
    }
    return abbrevs.get(rtype, rtype.replace("aws_", "")[:3].upper())


def svg_defs() -> str:
    return f'''  <defs>
    <marker id="arr" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
      <path d="M0,0 L0,6 L8,3 z" fill="{C['arrow']}"/>
    </marker>
    <filter id="drop" x="-10%" y="-10%" width="120%" height="130%">
      <feDropShadow dx="0" dy="1" stdDeviation="2" flood-opacity="0.1"/>
    </filter>
  </defs>'''


def svg_module(b: dict) -> str:
    x, y, w, h = b["x"], b["y"], b["w"], b["h"]
    return f'''  <g class="module">
    <rect x="{x}" y="{y}" width="{w}" height="{h}" fill="{C['module_bg']}" stroke="{C['module_border']}" rx="8"/>
    <path d="M{x+8},{y} h{w-16} a8,8 0 0 1 8,8 v{MODULE_HDR-8} h-{w} v-{MODULE_HDR-8} a8,8 0 0 1 8,-8 z" fill="{C['module_hdr']}"/>
    <text x="{x+16}" y="{y+22}" font-size="13" font-weight="600" fill="{C['text_inv']}">{esc(b['label'])}</text>
  </g>'''


def svg_node(p: dict) -> str:
    x, y = p["x"], p["y"]
    r = p["res"]
    rtype = r["type"]
    color = get_color(rtype)
    abbrev = get_abbrev(rtype)
    svc = SERVICE_LABELS.get(rtype, "")
    label = trunc(r.get("label", r["name"]))
    
    icon_x = x + (NODE_W - ICON_SIZE) // 2
    icon_y = y + 12
    
    return f'''  <g class="node">
    <rect x="{x}" y="{y}" width="{NODE_W}" height="{NODE_H}" fill="{C['node_bg']}" stroke="{C['node_border']}" rx="6" filter="url(#drop)"/>
    <rect x="{icon_x}" y="{icon_y}" width="{ICON_SIZE}" height="{ICON_SIZE}" rx="6" fill="{color}"/>
    <text x="{icon_x + ICON_SIZE//2}" y="{icon_y + 32}" font-size="16" font-weight="600" fill="white" text-anchor="middle">{abbrev}</text>
    <text x="{x + NODE_W//2}" y="{y + NODE_H - 24}" font-size="9" fill="{C['text2']}" text-anchor="middle">{esc(svc)}</text>
    <text x="{x + NODE_W//2}" y="{y + NODE_H - 10}" font-size="11" fill="{C['text']}" text-anchor="middle">{esc(label)}</text>
  </g>'''


def svg_path(points: List[Tuple[int, int]]) -> str:
    if len(points) < 2:
        return ""
    d = f"M{points[0][0]},{points[0][1]}"
    for px, py in points[1:]:
        d += f" L{px},{py}"
    return f'  <path d="{d}" fill="none" stroke="{C["arrow"]}" stroke-width="1.5" marker-end="url(#arr)"/>'


def svg_user(ux: int, uy: int) -> str:
    return f'''  <g class="user" transform="translate({ux},{uy})">
    <circle cx="24" cy="12" r="9" fill="none" stroke="{C['user']}" stroke-width="2"/>
    <path d="M8,38 Q8,24 24,24 Q40,24 40,38" fill="none" stroke="{C['user']}" stroke-width="2"/>
    <text x="24" y="54" font-size="11" fill="{C['text']}" text-anchor="middle">Users</text>
  </g>'''


def generate_svg(data: dict, title: str = None, show_user: bool = True) -> str:
    data = parse_state(data)
    L = layout(data, title)
    
    pos = L["pos"]
    w, h = int(L["w"]), int(L["h"])
    
    # Initialize routing grid
    grid = RoutingGrid(w, h)
    
    # Block all node areas
    for p in pos.values():
        grid.block_rect(p["x"], p["y"], NODE_W, NODE_H)
    
    # Block module headers
    for b in L["mods"].values():
        grid.block_rect(b["x"], b["y"], b["w"], MODULE_HDR)
    
    parts = [
        f'<?xml version="1.0" encoding="UTF-8"?>',
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" style="font-family: -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif;">',
        svg_defs(),
        f'  <rect width="100%" height="100%" fill="{C["bg"]}"/>',
    ]
    
    # Title
    if title:
        parts.append(f'  <text x="{CANVAS_PAD}" y="{L["title_y"]}" font-size="18" font-weight="600" fill="{C["text"]}">{esc(title)}</text>')
    
    # Modules (background layer)
    for b in L["mods"].values():
        parts.append(svg_module(b))
    
    # Nodes
    for p in pos.values():
        parts.append(svg_node(p))
    
    # Dependency arrows - using grid routing
    for dep in data.get("dependencies", []):
        fp, tp = pos.get(dep["from"]), pos.get(dep["to"])
        if fp and tp:
            x1, y1 = fp["r"] + 4, fp["cy"]
            x2, y2 = tp["l"] - 4, tp["cy"]
            
            # Use grid routing
            waypoints = grid.route(x1, y1, x2, y2)
            parts.append(svg_path(waypoints))
    
    # User and entry point arrows
    if show_user and pos:
        ux, uy = L["user"]["x"], L["user"]["y"]
        parts.append(svg_user(ux, uy))
        
        user_out_x = ux + 48
        user_out_y = uy + 24
        
        # Find entry points
        entries = [(addr, p) for addr, p in pos.items() if p["res"]["type"] in ENTRY_POINTS]
        
        for i, (addr, ep) in enumerate(entries):
            ex, ey = ep["l"] - 4, ep["cy"]
            
            # Stagger multiple arrows
            offset = (i - len(entries) // 2) * 8
            
            if abs(user_out_y - ey) < GRID * 2:
                # Same level - direct line
                parts.append(f'  <line x1="{user_out_x}" y1="{user_out_y}" x2="{ex}" y2="{ey}" stroke="{C["arrow"]}" stroke-width="1.5" marker-end="url(#arr)"/>')
            else:
                # Curved path to avoid overlaps
                mid_x = user_out_x + 20
                start_y = user_out_y + offset
                parts.append(f'  <path d="M{user_out_x},{start_y} L{mid_x},{start_y} Q{mid_x},{ey},{ex},{ey}" fill="none" stroke="{C["arrow"]}" stroke-width="1.5" marker-end="url(#arr)"/>')
    
    parts.append('</svg>')
    return '\n'.join(parts)


# =============================================================================
# CLI
# =============================================================================

def main():
    if len(sys.argv) < 3:
        print("Usage: terraform show -json | python tf2svg.py - output.svg", file=sys.stderr)
        print("       python tf2svg.py state.json output.svg [--title \"text\"] [--no-user]", file=sys.stderr)
        sys.exit(1)
    
    inp = sys.argv[1]
    out = Path(sys.argv[2])
    
    show_user = "--no-user" not in sys.argv
    title = None
    if "--title" in sys.argv:
        i = sys.argv.index("--title")
        if i + 1 < len(sys.argv):
            title = sys.argv[i + 1]
    
    if inp == "-":
        data = json.load(sys.stdin)
    else:
        p = Path(inp)
        if not p.exists():
            print(f"Error: {inp} not found", file=sys.stderr)
            sys.exit(1)
        data = json.loads(p.read_text())
    
    svg = generate_svg(data, title, show_user)
    out.write_text(svg)
    
    # Stats
    parsed = parse_state(data)
    res = [r for r in parsed.get("resources", []) if r["type"] in SHOW_RESOURCES]
    mods = set(r.get("module") or "_root" for r in res)
    print(f"✓ {out}", file=sys.stderr)
    print(f"  {len(res)} services, {len(mods)} modules", file=sys.stderr)


if __name__ == "__main__":
    main()