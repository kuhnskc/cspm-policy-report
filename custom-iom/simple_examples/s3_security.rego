package crowdstrike

# Simple S3 Bucket Security Policy
# Checks for basic S3 security best practices

default result := "pass"

# Fail if bucket allows public read access
result = "fail" if {
    input.resource_type == "AWS::S3::Bucket"
    input.configuration.publicAccessBlockConfiguration.blockPublicAcls == false
}

# Fail if bucket allows public write access
result = "fail" if {
    input.resource_type == "AWS::S3::Bucket"
    input.configuration.publicAccessBlockConfiguration.blockPublicPolicy == false
}

# Fail if bucket is missing Environment tag
result = "fail" if {
    input.resource_type == "AWS::S3::Bucket"
    not input.tags.Environment
}