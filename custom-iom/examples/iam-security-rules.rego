# IAM Security Rules
# Comprehensive Rego examples for AWS IAM user security and access management

package crowdstrike

# Rule 1: MFA Enforcement
# Requires Multi-Factor Authentication for human users

default mfa_result := "fail"

is_service_account if {
    startswith(input.resource_id, "svc-")
}

is_service_account if {
    startswith(input.resource_id, "service-")
}

is_service_account if {
    contains(lower(input.resource_id), "robot")
}

# Human users must have MFA
mfa_result := "pass" if {
    input.resource_type == "AWS::IAM::User"
    input.active == true
    not is_service_account
    input.cloud_context.mfa_enabled == true
}

# Service accounts with proper naming pass
mfa_result := "pass" if {
    input.resource_type == "AWS::IAM::User"
    input.active == true
    is_service_account
}

# Rule 2: Root Account Protection
# Prevents use of root account for daily operations

default root_usage_result := "fail"

root_usage_result := "pass" if {
    input.resource_type == "AWS::IAM::User"
    input.resource_id != "root"
}

# Rule 3: Administrative User Security
# Special requirements for users with elevated privileges

default admin_security_result := "fail"

is_admin_user if {
    contains(lower(input.resource_id), "admin")
}

is_admin_user if {
    policy := input.cloud_context.attached_policies[_]
    contains(lower(policy.name), "administrator")
}

admin_security_result := "pass" if {
    input.resource_type == "AWS::IAM::User"
    input.active == true
    not is_admin_user
}

admin_security_result := "pass" if {
    input.resource_type == "AWS::IAM::User"
    input.active == true
    is_admin_user
    input.cloud_context.mfa_enabled == true
    # Admin users should not have programmatic access
    count(input.cloud_context.access_keys) == 0
}

# Rule 4: Access Key Management
# Ensures proper lifecycle management of access keys

default access_key_result := "fail"

access_key_result := "pass" if {
    input.resource_type == "AWS::IAM::User"
    input.active == true
    # No access keys is always compliant
    count(input.cloud_context.access_keys) == 0
}

access_key_result := "pass" if {
    input.resource_type == "AWS::IAM::User"
    input.active == true
    count(input.cloud_context.access_keys) > 0
    # All keys must be recent and active
    key := input.cloud_context.access_keys[_]
    key.status == "Active"
    # Keys should be rotated (this is a placeholder - actual age calculation would need time functions)
    key.created_date != ""
}

# Rule 5: User Naming Conventions
# Enforces consistent naming patterns

default naming_result := "fail"

follows_human_naming if {
    not is_service_account
    # Human users should follow firstname.lastname or similar pattern
    contains(input.resource_id, ".")
    count(split(input.resource_id, ".")) == 2
}

follows_service_naming if {
    is_service_account
    startswith(input.resource_id, "svc-")
}

naming_result := "pass" if {
    input.resource_type == "AWS::IAM::User"
    input.active == true
    follows_human_naming
}

naming_result := "pass" if {
    input.resource_type == "AWS::IAM::User"
    input.active == true
    follows_service_naming
}

# Rule 6: Inactive User Detection
# Identifies users that haven't been used recently

default inactive_user_result := "fail"

# This would need actual time-based logic in production
inactive_user_result := "pass" if {
    input.resource_type == "AWS::IAM::User"
    input.active == true
    # Placeholder for activity check - would compare last_activity with current time
    input.cloud_context.last_activity != ""
}