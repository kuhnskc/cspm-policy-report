# AWS RDS Security Rules
# Advanced Rego policy for AWS RDS instances with comprehensive security controls
# Demonstrates complex logic patterns for CrowdStrike Custom IOMs

package crowdstrike

# Rule 1: Encryption at Rest and in Transit
# Ensures RDS instances have proper encryption configuration

default encryption_result := "fail"

encryption_result := "pass" if {
    input.resource_type == "AWS::RDS::DBInstance"
    input.active == true
    # Storage encryption must be enabled
    input.cloud_context.storage_encrypted == true
    # KMS key should be customer managed for production
    encryption_key_compliant
}

encryption_key_compliant if {
    input.tags["Environment"] in ["dev", "test"]
    # Development can use default keys
}

encryption_key_compliant if {
    input.tags["Environment"] in ["prod", "staging"]
    # Production should use customer managed KMS keys
    input.cloud_context.kms_key_id != ""
    not startswith(input.cloud_context.kms_key_id, "alias/aws/rds")
}

# Rule 2: Network Security Configuration
# Comprehensive network access controls

default network_security_result := "fail"

network_security_result := "pass" if {
    input.resource_type == "AWS::RDS::DBInstance"
    input.active == true
    # Must not be publicly accessible
    input.cloud_context.publicly_accessible == false
    # Must be in private subnets (subnet group validation)
    proper_subnet_configuration
    # Security groups should be restrictive
    security_group_compliant
}

proper_subnet_configuration if {
    input.cloud_context.db_subnet_group_name != ""
    # Subnet group should follow naming convention
    contains(input.cloud_context.db_subnet_group_name, "private")
}

security_group_compliant if {
    # Should not allow 0.0.0.0/0 access on database ports
    not wide_open_access
    # Should have at least one security group
    count(input.cloud_context.security_groups) > 0
}

wide_open_access if {
    sg := input.cloud_context.security_groups[_]
    rule := sg.ingress_rules[_]
    rule.cidr_blocks[_] == "0.0.0.0/0"
    database_port_exposed(rule.port)
}

database_port_exposed(port) if {
    # Common database ports
    port in [3306, 5432, 1433, 1521, 27017, 6379]
}

# Rule 3: Backup and Recovery Configuration
# Ensures proper backup policies and disaster recovery

default backup_result := "fail"

backup_result := "pass" if {
    input.resource_type == "AWS::RDS::DBInstance"
    input.active == true
    # Automated backups must be enabled
    input.cloud_context.backup_retention_period > 0
    # Backup retention appropriate for environment
    backup_retention_compliant
    # Backup window should be configured
    input.cloud_context.backup_window != ""
    # Point-in-time recovery for production
    point_in_time_recovery_compliant
}

backup_retention_compliant if {
    input.tags["Environment"] in ["dev", "test"]
    input.cloud_context.backup_retention_period >= 1
}

backup_retention_compliant if {
    input.tags["Environment"] in ["staging"]
    input.cloud_context.backup_retention_period >= 7
}

backup_retention_compliant if {
    input.tags["Environment"] == "prod"
    input.cloud_context.backup_retention_period >= 30
}

point_in_time_recovery_compliant if {
    input.tags["Environment"] in ["dev", "test"]
    # Not required for non-production
}

point_in_time_recovery_compliant if {
    input.tags["Environment"] in ["prod", "staging"]
    # Production should have point-in-time recovery
    input.cloud_context.backup_retention_period > 0
}

# Rule 4: Engine Version and Patching
# Ensures RDS instances run supported, patched engine versions

default version_result := "fail"

version_result := "pass" if {
    input.resource_type == "AWS::RDS::DBInstance"
    input.active == true
    # Auto minor version upgrade should be enabled
    input.cloud_context.auto_minor_version_upgrade == true
    # Engine version should be recent
    engine_version_current
    # Maintenance window should be configured
    input.cloud_context.maintenance_window != ""
}

engine_version_current if {
    # This is a simplified check - in reality would need to check against current versions
    input.cloud_context.engine_version != ""
    # Engine should not be approaching end of life
    not deprecated_engine_version
}

deprecated_engine_version if {
    # Example deprecated versions - would need to maintain current list
    input.cloud_context.engine == "mysql"
    version_parts := split(input.cloud_context.engine_version, ".")
    major_version := to_number(version_parts[0])
    major_version < 8
}

deprecated_engine_version if {
    input.cloud_context.engine == "postgres"
    version_parts := split(input.cloud_context.engine_version, ".")
    major_version := to_number(version_parts[0])
    major_version < 13
}

# Rule 5: Enhanced Monitoring and Logging
# Ensures comprehensive monitoring and audit logging

default monitoring_result := "fail"

has_tag(tag_name) if {
    input.tags[tag_name]
    input.tags[tag_name] != ""
}

monitoring_result := "pass" if {
    input.resource_type == "AWS::RDS::DBInstance"
    input.active == true
    # Enhanced monitoring for production
    enhanced_monitoring_compliant
    # Performance Insights for visibility
    performance_insights_compliant
    # CloudWatch logs should be exported
    log_exports_compliant
}

enhanced_monitoring_compliant if {
    input.tags["Environment"] in ["dev", "test"]
    # Optional for development
}

enhanced_monitoring_compliant if {
    input.tags["Environment"] in ["prod", "staging"]
    input.cloud_context.monitoring_interval > 0
    input.cloud_context.monitoring_role_arn != ""
}

performance_insights_compliant if {
    input.tags["Environment"] in ["dev", "test"]
    # Optional for development
}

performance_insights_compliant if {
    input.tags["Environment"] in ["prod", "staging"]
    input.cloud_context.performance_insights_enabled == true
}

log_exports_compliant if {
    # At minimum should export error logs
    count(input.cloud_context.enabled_cloudwatch_logs_exports) > 0
}

# Rule 6: Multi-AZ and High Availability
# Ensures proper high availability configuration

default ha_result := "fail"

ha_result := "pass" if {
    input.resource_type == "AWS::RDS::DBInstance"
    input.active == true
    multi_az_compliant
    # Deletion protection for production
    deletion_protection_compliant
}

multi_az_compliant if {
    input.tags["Environment"] in ["dev", "test"]
    # Single AZ acceptable for development
}

multi_az_compliant if {
    input.tags["Environment"] in ["prod", "staging"]
    input.cloud_context.multi_az == true
}

deletion_protection_compliant if {
    input.tags["Environment"] in ["dev", "test"]
    # Deletion protection not required for development
}

deletion_protection_compliant if {
    input.tags["Environment"] in ["prod", "staging"]
    input.cloud_context.deletion_protection == true
}

# Rule 7: Instance Class and Cost Optimization
# Ensures appropriate instance sizing and cost controls

default instance_sizing_result := "fail"

instance_sizing_result := "pass" if {
    input.resource_type == "AWS::RDS::DBInstance"
    input.active == true
    instance_class_appropriate
    # Proper tagging for cost allocation
    has_tag("CostCenter")
    has_tag("BusinessUnit")
}

instance_class_appropriate if {
    input.tags["Environment"] in ["dev", "test"]
    # Development should use smaller, burstable instances
    startswith(input.cloud_context.db_instance_class, "db.t3")
}

instance_class_appropriate if {
    input.tags["Environment"] == "staging"
    # Staging can use medium instances
    instance_class_allowed_staging
}

instance_class_appropriate if {
    input.tags["Environment"] == "prod"
    # Production needs approval for large instances
    production_instance_approved
}

instance_class_allowed_staging if {
    allowed_staging := ["db.t3.medium", "db.t3.large", "db.r5.large", "db.r5.xlarge"]
    input.cloud_context.db_instance_class in allowed_staging
}

production_instance_approved if {
    # Small to medium instances are always allowed
    allowed_prod := ["db.r5.large", "db.r5.xlarge", "db.r5.2xlarge"]
    input.cloud_context.db_instance_class in allowed_prod
}

production_instance_approved if {
    # Large instances need approval
    has_tag("LargeInstanceApproved")
    input.tags["LargeInstanceApproved"] == "true"
}