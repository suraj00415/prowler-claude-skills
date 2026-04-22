# Prowler Finding Analyzer

Analyze Prowler scan findings and cross-verify with AWS CLI to determine if they are true positives or false positives.

## Arguments

$ARGUMENTS

Parse the arguments as follows:
- **file**: (REQUIRED) Path to the Prowler output CSV file (semicolon-delimited). Can be absolute or relative to the prowler-output/ directory.
- **profile**: (REQUIRED) AWS CLI profile name to use for verification queries.
- **service**: (OPTIONAL) Filter by AWS service name. Comma-separated for multiple services (e.g., "ec2,s3,iam"). Supported: ec2, s3, iam, rds, lambda, cloudtrail, cloudwatch, efs, eks, elb, elbv2, kms, sns, sqs, vpc, guardduty, config, etc. If omitted, analyze all services.
- **status**: (OPTIONAL) Filter by finding status: FAIL or PASS. If omitted, defaults to FAIL only.
- **severity**: (OPTIONAL) Filter by severity: critical, high, medium, low. Comma-separated for multiple (e.g., "critical,high"). If omitted, defaults to critical and high.
- **check**: (OPTIONAL) Filter by specific CHECK_ID pattern (e.g., "ec2_instance_port_ssh" or "s3_bucket_public"). Supports partial match.
- **external-profile**: (OPTIONAL) A second AWS profile that belongs to a DIFFERENT AWS organization/account (external, untrusted). Used for cross-account verification of S3 bucket access, public snapshots, public AMIs, etc. If not provided, skip external-account checks but note they were skipped.
- **limit**: (OPTIONAL) Max number of findings to analyze in detail. Defaults to 10. Use "all" for no limit.
- **region**: (OPTIONAL) Override region for AWS CLI calls. If omitted, use the region from each finding.

### Argument format examples:
```
/prowler file=prowler-output-331560656580-20260422044210.csv profile=poc
/prowler file=prowler-output-331560656580-20260422044210.csv profile=poc service=ec2 severity=critical
/prowler file=prowler-output-331560656580-20260422044210.csv profile=poc service=ec2,s3,iam severity=critical,high
/prowler file=prowler-output-331560656580-20260422044210.csv profile=poc service=s3 external-profile=external-pentest
/prowler file=prowler-output-331560656580-20260422044210.csv profile=poc status=FAIL severity=critical,high check=ssh limit=5
```

## Procedure

### Step 1: Parse and filter the Prowler CSV

1. Read the CSV file (semicolon-delimited with these key columns):
   - `STATUS` (col index 13): PASS or FAIL
   - `SERVICE_NAME` (col index 16): e.g., ec2, s3, iam
   - `SEVERITY` (col index 18): critical, high, medium, low
   - `CHECK_ID` (col index 10): the specific check identifier
   - `STATUS_EXTENDED` (col index 14): human-readable finding detail
   - `RESOURCE_UID` (col index 20): ARN or resource identifier
   - `RESOURCE_NAME` (col index 21): resource name
   - `RESOURCE_TAGS` (col index 23): resource tags
   - `REGION` (col index 25): AWS region
   - `ACCOUNT_UID` (col index 2): AWS account ID
   - `RISK` (col index 27): risk description
   - `REMEDIATION_CODE_CLI` (col index 33): AWS CLI remediation command

2. Apply filters based on user arguments. Default to status=FAIL and severity=critical,high if not specified.

3. Print a summary table of filtered findings: count by CHECK_ID, severity, and region.

4. If more findings than the limit, pick the most critical ones and inform the user how many were skipped.

### Step 2: Cross-verify each finding with AWS CLI

For EACH filtered finding, run verification commands using `aws --profile <profile> --region <region>`. Always use the region from the finding unless overridden.

#### EC2 Findings verification matrix:

**Port exposure checks** (CHECK_ID matches `ec2_instance_port_*_exposed_to_internet`):
1. Verify instance exists and is running: `aws ec2 describe-instances --instance-ids <id>`
2. Check if instance has a public IP
3. Get all attached Security Groups and check inbound rules for the specific port with 0.0.0.0/0 or ::/0
4. Check subnet route table for IGW (internet gateway) route
5. Check Network ACLs for deny rules on the port
6. **Verdict**: TRUE POSITIVE if SG allows 0.0.0.0/0 on the port AND instance has public IP AND subnet has IGW route AND no NACL deny. Otherwise explain which layer blocks it.

**Security Group checks** (CHECK_ID matches `ec2_securitygroup_*`):
1. Verify the security group exists: `aws ec2 describe-security-groups --group-ids <sg-id>`
2. Check the specific inbound rules flagged
3. Check if the SG is actually attached to any running resource: `aws ec2 describe-network-interfaces --filters Name=group-id,Values=<sg-id>`
4. **Verdict**: TRUE POSITIVE if the rule exists. Note if the SG is unused (not attached to anything) as lower risk.

**EC2 instance public IP** (`ec2_instance_public_ip`):
1. Verify the instance and its public IP
2. Check if in a public subnet with IGW
3. Check what SG rules are attached (any open ports?)

**EBS encryption/snapshot checks**:
1. Verify the volume/snapshot exists
2. Check encryption status: `aws ec2 describe-volumes` or `aws ec2 describe-snapshots`
3. For public snapshots: `aws ec2 describe-snapshot-attribute --attribute createVolumePermission`

**AMI public checks** (`ec2_ami_public`):
1. Check AMI launch permissions: `aws ec2 describe-image-attribute --image-id <ami-id> --attribute launchPermission`
2. If external-profile is provided, try: `aws ec2 describe-images --image-ids <ami-id> --profile <external-profile>` to confirm external access

**IMDS checks** (`ec2_instance_imdsv2_enabled`):
1. Check instance metadata options: `aws ec2 describe-instances` and look at `MetadataOptions.HttpTokens`
2. TRUE POSITIVE if HttpTokens is "optional" (IMDSv1 still allowed)

#### S3 Findings verification matrix:

**S3 bucket public access / policy checks**:
1. Check bucket public access block: `aws s3api get-public-access-block --bucket <name>`
2. Check bucket ACL: `aws s3api get-bucket-acl --bucket <name>`
3. Check bucket policy: `aws s3api get-bucket-policy --bucket <name>` and analyze for public access (Principal: "*")
4. **Unauthenticated check**: Use curl to test anonymous access:
   - `curl -s -o /dev/null -w "%{http_code}" https://<bucket>.s3.amazonaws.com/`
   - `curl -s -o /dev/null -w "%{http_code}" https://<bucket>.s3.<region>.amazonaws.com/?list-type=2`
5. **External account check** (if external-profile provided):
   - `aws s3 ls s3://<bucket>/ --profile <external-profile> --no-sign-request` (anonymous)
   - `aws s3 ls s3://<bucket>/ --profile <external-profile>` (authenticated external account)
   - `aws s3api get-object --bucket <bucket> --key <test-key> /dev/null --profile <external-profile>` if listing succeeds
6. Check S3 account-level public access block: `aws s3control get-public-access-block --account-id <account-id>`

**S3 encryption checks**:
1. Check default encryption: `aws s3api get-bucket-encryption --bucket <name>`

**S3 logging/versioning checks**:
1. Verify with respective API calls

#### IAM Findings verification matrix:
1. For overly permissive policies: `aws iam get-policy-version` and analyze the policy document
2. For unused credentials: `aws iam get-credential-report` or `aws iam get-access-key-last-used`
3. For MFA checks: `aws iam list-mfa-devices`

#### RDS Findings verification matrix:
1. Check public accessibility: `aws rds describe-db-instances` and check `PubliclyAccessible` flag
2. Check encryption: look at `StorageEncrypted`
3. For public access, also verify SG rules and subnet routing

#### Lambda / CloudTrail / CloudWatch / Other services:
- Use the appropriate `aws <service> describe-*` commands to verify the specific configuration flagged by Prowler.

### Step 3: Generate the verdict report

For EACH finding analyzed, output a structured report:

```
---
### Finding: <CHECK_ID>
**Resource**: <RESOURCE_UID> (<RESOURCE_NAME>)
**Region**: <REGION>
**Severity**: <SEVERITY>
**Prowler Says**: <STATUS_EXTENDED>

**Verification Steps Performed**:
1. <what you checked> -> <result>
2. <what you checked> -> <result>
...

**External Access Test** (if applicable):
- Anonymous: <result>
- Cross-account (<external-profile>): <result>

**Verdict**: TRUE POSITIVE / FALSE POSITIVE / PARTIALLY TRUE
**Confidence**: HIGH / MEDIUM / LOW
**Reason**: <one-line explanation>
**Risk Level**: CRITICAL / HIGH / MEDIUM / LOW / INFORMATIONAL
**Recommendation**: <action to take>
---
```

### Step 4: Summary

After all findings are analyzed, output a summary table:

```
## Summary
| # | CHECK_ID | Resource | Verdict | Confidence | Risk |
|---|----------|----------|---------|------------|------|
| 1 | ...      | ...      | ...     | ...        | ...  |
```

And a final count:
- Total findings analyzed: X
- True Positives: X
- False Positives: X
- Partially True: X
- Skipped (over limit): X

## Important notes

- Always use `--profile` and `--region` flags on every AWS CLI call.
- If a resource is not found (terminated/deleted), mark as "RESOURCE NOT FOUND - likely terminated since scan" and note it may have been a true positive at scan time.
- For EC2 port exposure findings, ALWAYS check all 4 layers: Security Group, NACL, Route Table (IGW), and Public IP.
- For S3, ALWAYS try both authenticated (org account) AND unauthenticated access if possible.
- Rate limit yourself: add brief pauses between API calls if you're making many calls.
- If you encounter AccessDenied on any check, note it in the report and explain what permission is missing.
- Group similar findings (e.g., same SG flagged multiple times) and verify once, apply verdict to all.
- Parse the CSV using Python with the csv module since the fields contain semicolons, newlines, and complex content.
