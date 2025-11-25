package crowdstrike

# ECR Cross-Account Access Control Policy
# Prevents unauthorized AWS accounts from accessing ECR repositories

# Define approved AWS accounts for cross-account access
approved_accounts := {
    "517716713836"  # QantasLoyalty qlmgt account
    # Add more approved accounts here as needed
}

default result := "pass"

# Parse the ECR registry policy document
policy_doc := json.unmarshal(input.configuration.policyText)

# Extract AWS account IDs from policy principals
principal_accounts contains account_id if {
    statement := policy_doc.Statement[_]
    statement.Effect == "Allow"
    principal := statement.Principal.AWS
    is_string(principal)
    startswith(principal, "arn:aws:iam::")
    parts := split(principal, ":")
    account_id := parts[4]
}

# Find accounts that are NOT approved
unauthorized_accounts := principal_accounts - approved_accounts

# Fail if any unauthorized accounts are found
result = "fail" if {
    input.resource_type == "AWS::ECR::RegistryPolicy"
    count(unauthorized_accounts) > 0
}