# Prowler Finding Analyzer - Claude Code Guidelines

## AWS Safety Rules (CRITICAL)

- **READ-ONLY**: Only use AWS CLI read/describe/get/list API calls. NEVER use create, delete, modify, update, put, revoke, authorize, terminate, stop, start, or any mutating API call.
- **No infrastructure changes**: Do not create, modify, or delete any AWS resource. This tool is strictly for **evaluation and verification** of Prowler findings.
- **No remediation execution**: When providing remediation commands, present them as recommendations for the user to review and run manually. NEVER execute remediation commands.
- **No security group changes**: Do not run `authorize-security-group-ingress`, `revoke-security-group-ingress`, or any SG modification.
- **No S3 writes**: Do not upload, delete, or modify any S3 objects or bucket configurations.
- **No IAM changes**: Do not create/delete users, roles, policies, or access keys.

### Allowed API patterns (whitelist)
```
aws ec2 describe-*
aws ec2 get-*
aws s3api get-*
aws s3api list-*
aws s3api head-*
aws s3 ls
aws iam get-*
aws iam list-*
aws rds describe-*
aws lambda get-*
aws lambda list-*
aws cloudtrail describe-*
aws cloudtrail get-*
aws cloudwatch describe-*
aws sts get-caller-identity
aws s3control get-*
```

### Explicitly forbidden API patterns (blocklist)
```
aws * create-*
aws * delete-*
aws * modify-*
aws * update-*
aws * put-*
aws * remove-*
aws * revoke-*
aws * authorize-*
aws * terminate-*
aws * stop-*
aws * start-*
aws * attach-*
aws * detach-*
aws * enable-*
aws * disable-*
aws * deregister-*
aws * run-*
```

## External access testing

- **Anonymous S3 checks**: Use `curl` with HTTP HEAD/GET only. Do not upload anything.
- **Cross-account checks**: Only use `aws s3 ls` and `aws s3api get-*` / `aws s3api head-*` with the external profile. Never write to or delete from any bucket.
- **No port scanning tools**: Do not run nmap, masscan, or similar tools against AWS resources. Use AWS API to determine exposure instead.

## Prowler CSV format

- Semicolon-delimited (`;`)
- Always parse with Python `csv` module since fields contain embedded newlines, semicolons, and complex content
- Key column indices: STATUS(13), SERVICE_NAME(16), SEVERITY(18), CHECK_ID(10), RESOURCE_UID(20), REGION(25)

## General behavior

- Always use `--profile` and `--region` on every AWS CLI call
- If AccessDenied, report it - do not attempt workarounds
- Group identical findings (same SG, same resource) and verify once
- Present findings in structured verdict format with confidence levels
