# AWS Lambda Security Rules
# Comprehensive Rego examples for AWS Lambda function security and compliance
# Created as a custom IOM demonstration following CrowdStrike CSPM patterns

package crowdstrike

# Rule 1: Environment Variable Security
# Ensures Lambda functions don't expose sensitive data in environment variables

default env_security_result := "fail"

contains_sensitive_pattern(value) if {
    patterns := ["password", "secret", "key", "token", "credential", "api_key", "private"]
    pattern := patterns[_]
    contains(lower(value), pattern)
}

env_security_result := "pass" if {
    input.resource_type == "AWS::Lambda::Function"
    input.active == true
    # Check if any environment variable names contain sensitive patterns
    not env_var_name_violation
    # Check if any environment variable values are potentially exposed
    not env_var_value_violation
}

env_var_name_violation if {
    env_var := input.cloud_context.environment.variables[name]
    contains_sensitive_pattern(name)
}

env_var_value_violation if {
    env_var := input.cloud_context.environment.variables[name]
    # Values should not contain obvious sensitive patterns
    contains_sensitive_pattern(env_var)
    # Values should not be empty or default
    env_var != ""
}

# Rule 2: Runtime and Version Security
# Ensures Lambda functions use supported, secure runtimes

default runtime_security_result := "fail"

supported_runtimes := [
    "python3.9", "python3.10", "python3.11", "python3.12",
    "nodejs18.x", "nodejs20.x",
    "java11", "java17", "java21",
    "dotnet6", "dotnet8",
    "go1.x",
    "ruby3.2", "ruby3.3"
]

runtime_security_result := "pass" if {
    input.resource_type == "AWS::Lambda::Function"
    input.active == true
    input.cloud_context.runtime in supported_runtimes
}

# Rule 3: VPC Configuration Security
# Ensures proper network security for Lambda functions

default vpc_security_result := "fail"

# Functions not in VPC should have proper justification via tagging
vpc_security_result := "pass" if {
    input.resource_type == "AWS::Lambda::Function"
    input.active == true
    not input.cloud_context.vpc_config
    has_tag("VPCExemption")
    input.tags["VPCExemption"] in ["approved", "public-api", "edge-function"]
}

# Functions in VPC should have proper security group configuration
vpc_security_result := "pass" if {
    input.resource_type == "AWS::Lambda::Function"
    input.active == true
    input.cloud_context.vpc_config
    count(input.cloud_context.vpc_config.security_group_ids) > 0
    count(input.cloud_context.vpc_config.subnet_ids) >= 2  # Multi-AZ for resilience
}

# Rule 4: Execution Role Security
# Ensures Lambda functions follow least-privilege principle

default execution_role_result := "fail"

has_tag(tag_name) if {
    input.tags[tag_name]
    input.tags[tag_name] != ""
}

execution_role_result := "pass" if {
    input.resource_type == "AWS::Lambda::Function"
    input.active == true
    # Role should not be the default lambda service role
    not contains(input.cloud_context.role, "lambda-basic-execution-role")
    # Should have proper tagging for role justification
    has_tag("RoleReviewed")
    input.tags["RoleReviewed"] == "approved"
}

# Rule 5: Timeout and Memory Configuration
# Ensures appropriate resource limits

default resource_config_result := "fail"

resource_config_result := "pass" if {
    input.resource_type == "AWS::Lambda::Function"
    input.active == true
    # Timeout should be reasonable (not max 15 minutes unless justified)
    timeout_check
    # Memory should be appropriate for function type
    memory_check
}

timeout_check if {
    input.cloud_context.timeout <= 300  # 5 minutes for most functions
}

timeout_check if {
    input.cloud_context.timeout > 300
    has_tag("LongRunningApproved")
    input.tags["LongRunningApproved"] == "true"
}

memory_check if {
    input.cloud_context.memory_size >= 128
    input.cloud_context.memory_size <= 3008
}

# Rule 6: Tagging Compliance
# Ensures Lambda functions have required governance tags

default lambda_tagging_result := "fail"

required_lambda_tags := ["Environment", "Owner", "Project", "CostCenter", "FunctionType"]

lambda_tagging_result := "pass" if {
    input.resource_type == "AWS::Lambda::Function"
    input.active == true
    count([tag | tag := required_lambda_tags[_]; has_tag(tag)]) == count(required_lambda_tags)
    input.tags["Environment"] in ["dev", "staging", "prod", "test"]
    input.tags["FunctionType"] in ["api", "event-processor", "scheduled", "utility", "integration"]
}

# Rule 7: Dead Letter Queue Configuration
# Ensures proper error handling for asynchronous invocations

default dlq_config_result := "fail"

# Synchronous functions (API Gateway, etc.) don't need DLQ
dlq_config_result := "pass" if {
    input.resource_type == "AWS::Lambda::Function"
    input.active == true
    input.tags["FunctionType"] in ["api", "utility"]
}

# Asynchronous functions should have DLQ configured
dlq_config_result := "pass" if {
    input.resource_type == "AWS::Lambda::Function"
    input.active == true
    input.tags["FunctionType"] in ["event-processor", "scheduled", "integration"]
    input.cloud_context.dead_letter_config.target_arn != ""
}

# Rule 8: Reserved Concurrency
# Prevents runaway costs and ensures appropriate scaling

default concurrency_result := "fail"

concurrency_result := "pass" if {
    input.resource_type == "AWS::Lambda::Function"
    input.active == true
    # Development and test environments should have concurrency limits
    input.tags["Environment"] in ["dev", "test"]
    input.cloud_context.reserved_concurrency
    input.cloud_context.reserved_concurrency <= 10
}

concurrency_result := "pass" if {
    input.resource_type == "AWS::Lambda::Function"
    input.active == true
    # Production can have higher limits but should be set
    input.tags["Environment"] in ["prod", "staging"]
    input.cloud_context.reserved_concurrency
    input.cloud_context.reserved_concurrency <= 100
}

# Allow unlimited concurrency only with explicit approval
concurrency_result := "pass" if {
    input.resource_type == "AWS::Lambda::Function"
    input.active == true
    not input.cloud_context.reserved_concurrency
    has_tag("UnlimitedConcurrencyApproved")
    input.tags["UnlimitedConcurrencyApproved"] == "true"
}