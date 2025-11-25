package crowdstrike

# Simple EC2 Instance Tagging Policy
# Ensures EC2 instances have proper tags for governance

default result := "pass"

# Fail if instance is missing Environment tag
result = "fail" if {
    input.resource_type == "AWS::EC2::Instance"
    not input.tags.Environment
}

# Fail if Environment tag has invalid value
result = "fail" if {
    input.resource_type == "AWS::EC2::Instance"
    input.tags.Environment
    not input.tags.Environment in ["dev", "staging", "prod"]
}

# Fail if production instance is missing Owner tag
result = "fail" if {
    input.resource_type == "AWS::EC2::Instance"
    input.tags.Environment == "prod"
    not input.tags.Owner
}