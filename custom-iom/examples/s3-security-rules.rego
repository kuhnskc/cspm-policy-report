# S3 Bucket Security Rules
# Comprehensive Rego examples for AWS S3 bucket security and compliance

package crowdstrike

# Rule 1: Public Access Prevention
# Prevents S3 buckets from allowing public read or write access

default public_access_result := "fail"

public_access_result := "pass" if {
    input.resource_type == "AWS::S3::Bucket"
    input.active == true
    input.cloud_context.allows_public_read == false
    input.cloud_context.allows_public_write == false
}

# Rule 2: Encryption Requirements
# Ensures S3 buckets have encryption enabled

default encryption_result := "fail"

encryption_result := "pass" if {
    input.resource_type == "AWS::S3::Bucket"
    input.active == true
    input.cloud_context.encryption.enabled == true
    input.cloud_context.encryption.type in ["AES256", "aws:kms"]
}

# Rule 3: Tagging Compliance
# Requires specific tags on S3 buckets for governance

default tagging_result := "fail"

required_s3_tags := ["Environment", "Owner", "DataClassification", "Project"]

has_tag(tag_name) if {
    input.tags[tag_name]
    input.tags[tag_name] != ""
}

tagging_result := "pass" if {
    input.resource_type == "AWS::S3::Bucket"
    input.active == true
    count([tag | tag := required_s3_tags[_]; has_tag(tag)]) == count(required_s3_tags)
    input.tags["Environment"] in ["dev", "staging", "prod", "test"]
    input.tags["DataClassification"] in ["public", "internal", "confidential", "restricted"]
}

# Rule 4: Versioning and Logging
# Ensures proper versioning and access logging for audit trails

default versioning_result := "fail"

versioning_result := "pass" if {
    input.resource_type == "AWS::S3::Bucket"
    input.active == true
    input.cloud_context.versioning.enabled == true
    input.cloud_context.logging.enabled == true
}

# Rule 5: Cross-Region Replication Compliance
# Ensures critical buckets have cross-region replication

default replication_result := "fail"

replication_result := "pass" if {
    input.resource_type == "AWS::S3::Bucket"
    input.active == true
    # Non-critical environments don't need replication
    input.tags["Environment"] in ["dev", "test"]
}

replication_result := "pass" if {
    input.resource_type == "AWS::S3::Bucket"
    input.active == true
    input.tags["Environment"] in ["prod", "staging"]
    input.cloud_context.replication.enabled == true
}