# EC2 Instance Compliance Rules
# Comprehensive Rego examples for AWS EC2 instance security and governance

package crowdstrike

# Rule 1: Required Tagging
# Ensures EC2 instances have all required tags for management

default tagging_result := "fail"

required_ec2_tags := ["Environment", "Owner", "Project", "CostCenter"]

has_tag(tag_name) if {
    input.tags[tag_name]
    input.tags[tag_name] != ""
}

tagging_result := "pass" if {
    input.resource_type == "AWS::EC2::Instance"
    input.active == true
    count([tag | tag := required_ec2_tags[_]; has_tag(tag)]) == count(required_ec2_tags)
    input.tags["Environment"] in ["dev", "staging", "prod", "test"]
}

# Rule 2: Instance Type Compliance
# Enforces appropriate instance types per environment

default instance_type_result := "fail"

# Development instances should use smaller, cost-effective types
instance_type_result := "pass" if {
    input.resource_type == "AWS::EC2::Instance"
    input.active == true
    input.tags["Environment"] in ["dev", "test"]
    input.cloud_context.instance_type in [
        "t3.micro", "t3.small", "t3.medium",
        "t4g.micro", "t4g.small", "t4g.medium"
    ]
}

# Production instances need proper approval
instance_type_result := "pass" if {
    input.resource_type == "AWS::EC2::Instance"
    input.active == true
    input.tags["Environment"] == "prod"
    has_tag("InstanceTypeApproved")
    input.tags["InstanceTypeApproved"] == "true"
}

# Rule 3: Security Configuration
# Ensures instances follow security best practices

default security_result := "fail"

security_result := "pass" if {
    input.resource_type == "AWS::EC2::Instance"
    input.active == true
    # IMDSv2 should be enforced
    input.cloud_context.metadata_options.http_tokens == "required"
    # Monitoring should be enabled
    input.cloud_context.monitoring_enabled == true
    # Should not have public IP unless approved
    not has_public_ip_without_approval
}

has_public_ip_without_approval if {
    input.cloud_context.network_interfaces[_].public_ip
    not has_tag("PublicIPApproved")
}

# Rule 4: Patch Compliance
# Ensures instances are configured for proper patch management

default patch_result := "fail"

patch_result := "pass" if {
    input.resource_type == "AWS::EC2::Instance"
    input.active == true
    # Production instances need patch management tags
    input.tags["Environment"] != "prod"
}

patch_result := "pass" if {
    input.resource_type == "AWS::EC2::Instance"
    input.active == true
    input.tags["Environment"] == "prod"
    has_tag("PatchGroup")
    has_tag("MaintenanceWindow")
}

# Rule 5: Cost Optimization
# Ensures proper cost controls and auto-shutdown for non-prod

default cost_result := "fail"

cost_result := "pass" if {
    input.resource_type == "AWS::EC2::Instance"
    input.active == true
    input.tags["Environment"] == "prod"
    # Production instances are exempt from auto-shutdown
}

cost_result := "pass" if {
    input.resource_type == "AWS::EC2::Instance"
    input.active == true
    input.tags["Environment"] in ["dev", "test", "staging"]
    has_tag("AutoShutdown")
    input.tags["AutoShutdown"] in ["enabled", "true"]
    has_tag("Schedule")
}