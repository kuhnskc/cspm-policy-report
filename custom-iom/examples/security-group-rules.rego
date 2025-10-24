# Security Group Validation Rules
# Comprehensive Rego examples for AWS Security Group compliance and network security

package crowdstrike

# Rule 1: Dangerous Port Restrictions
# Prevents unrestricted access to high-risk ports

default dangerous_ports_result := "fail"

dangerous_ports := [
    22,    # SSH
    3389,  # RDP
    1433,  # SQL Server
    3306,  # MySQL
    5432,  # PostgreSQL
    1521,  # Oracle
    27017, # MongoDB
    6379,  # Redis
    5984,  # CouchDB
    9200   # Elasticsearch
]

has_unrestricted_dangerous_access if {
    rule := input.cloud_context.ingress_rules[_]
    rule.cidr_blocks[_] == "0.0.0.0/0"
    rule.port in dangerous_ports
}

dangerous_ports_result := "pass" if {
    input.resource_type == "AWS::EC2::SecurityGroup"
    input.active == true
    not has_unrestricted_dangerous_access
    has_proper_description
}

has_proper_description if {
    input.cloud_context.description != ""
    input.cloud_context.description != "default"
    count(input.cloud_context.description) >= 10
}

# Rule 2: Web Traffic Validation
# Allows HTTP/HTTPS but validates other access patterns

default web_traffic_result := "fail"

allows_web_traffic if {
    rule := input.cloud_context.ingress_rules[_]
    rule.cidr_blocks[_] == "0.0.0.0/0"
    rule.port in [80, 443]
}

allows_non_web_unrestricted if {
    rule := input.cloud_context.ingress_rules[_]
    rule.cidr_blocks[_] == "0.0.0.0/0"
    not rule.port in [80, 443]
}

web_traffic_result := "pass" if {
    input.resource_type == "AWS::EC2::SecurityGroup"
    input.active == true
    allows_web_traffic
    not allows_non_web_unrestricted
    has_web_purpose_tag
}

has_web_purpose_tag if {
    input.tags["Purpose"] in ["web", "loadbalancer", "public-web", "alb", "elb", "frontend"]
}

# Rule 3: Internal Security Groups
# Validates security groups for private/internal resources

default internal_sg_result := "fail"

is_internal_sg if {
    not has_public_access
    input.tags["NetworkTier"] in ["private", "internal", "database", "backend"]
}

has_public_access if {
    rule := input.cloud_context.ingress_rules[_]
    rule.cidr_blocks[_] == "0.0.0.0/0"
}

follows_internal_sg_rules if {
    # All ingress should be from specific sources, not 0.0.0.0/0
    rule := input.cloud_context.ingress_rules[_]
    not rule.cidr_blocks[_] == "0.0.0.0/0"
}

internal_sg_result := "pass" if {
    input.resource_type == "AWS::EC2::SecurityGroup"
    input.active == true
    is_internal_sg
    follows_internal_sg_rules
    has_required_internal_tags
}

has_required_internal_tags if {
    required_tags := ["Environment", "Owner", "Purpose", "NetworkTier"]
    count([tag | tag := required_tags[_]; input.tags[tag]]) == count(required_tags)
}

# Rule 4: Naming Convention Compliance
# Enforces consistent security group naming patterns

default naming_convention_result := "fail"

follows_naming_pattern if {
    # Pattern: env-purpose-component (e.g., prod-web-alb, dev-db-mysql)
    parts := split(input.resource_id, "-")
    count(parts) >= 3
    parts[0] in ["dev", "staging", "prod", "test"]
    parts[1] in ["web", "app", "db", "cache", "lb", "mgmt"]
}

is_default_sg if {
    input.resource_id == "default"
}

naming_convention_result := "pass" if {
    input.resource_type == "AWS::EC2::SecurityGroup"
    input.active == true
    follows_naming_pattern
    not is_default_sg
}

# Rule 5: Egress Rules Validation
# Ensures appropriate egress restrictions

default egress_rules_result := "fail"

has_controlled_egress if {
    # Either no egress rules (very restrictive) or specific rules
    count(input.cloud_context.egress_rules) == 0
}

has_controlled_egress if {
    # Has specific egress rules that aren't overly broad
    count(input.cloud_context.egress_rules) > 0
    not has_unrestricted_egress
}

has_unrestricted_egress if {
    rule := input.cloud_context.egress_rules[_]
    rule.cidr_blocks[_] == "0.0.0.0/0"
    rule.port == -1  # All ports
    rule.protocol == "-1"  # All protocols
}

egress_rules_result := "pass" if {
    input.resource_type == "AWS::EC2::SecurityGroup"
    input.active == true
    has_controlled_egress
}

# Rule 6: Environment-Specific Validation
# Different security requirements based on environment

default environment_specific_result := "fail"

# Development - more relaxed but still secure
environment_specific_result := "pass" if {
    input.resource_type == "AWS::EC2::SecurityGroup"
    input.active == true
    input.tags["Environment"] in ["dev", "test"]
    not has_unrestricted_dangerous_access
    has_basic_tags
}

# Production - strict requirements
environment_specific_result := "pass" if {
    input.resource_type == "AWS::EC2::SecurityGroup"
    input.active == true
    input.tags["Environment"] == "prod"
    not has_unrestricted_dangerous_access
    not has_unrestricted_egress
    has_production_tags
    has_change_approval
}

has_basic_tags if {
    basic_tags := ["Environment", "Owner", "Purpose"]
    count([tag | tag := basic_tags[_]; input.tags[tag]]) == count(basic_tags)
}

has_production_tags if {
    prod_tags := ["Environment", "Owner", "Purpose", "ChangeRequest", "ApprovedBy"]
    count([tag | tag := prod_tags[_]; input.tags[tag]]) == count(prod_tags)
}

has_change_approval if {
    input.tags["ApprovedBy"] != ""
    input.tags["ChangeRequest"] != ""
}