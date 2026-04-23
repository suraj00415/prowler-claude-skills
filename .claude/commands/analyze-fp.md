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
- **external-profile**: (OPTIONAL but **STRONGLY RECOMMENDED for S3 findings**) A second AWS CLI profile that belongs to a DIFFERENT AWS account that is **NOT in the same AWS Organization** as the target account. Used for cross-account verification of S3 bucket access, public snapshots, public AMIs, etc. This simulates what an authenticated but unauthorized AWS user can access. If not provided, skip external-account checks but **warn the user** that S3 cross-account verification was skipped and results may be incomplete — a bucket could appear locked down from within the org but still be accessible to any authenticated AWS user outside the org.
- **limit**: (OPTIONAL) Max number of findings to analyze in detail. Defaults to 10. Use "all" for no limit.
- **region**: (OPTIONAL) Override region for AWS CLI calls. If omitted, use the region from each finding.

### Argument format examples:
```
/analyze-fp file=prowler-output-331560656580-20260422044210.csv profile=poc
/analyze-fp file=prowler-output-331560656580-20260422044210.csv profile=poc service=ec2 severity=critical
/analyze-fp file=prowler-output-331560656580-20260422044210.csv profile=poc service=ec2,s3,iam severity=critical,high
/analyze-fp file=prowler-output-331560656580-20260422044210.csv profile=poc service=s3 external-profile=external-pentest
/analyze-fp file=prowler-output-331560656580-20260422044210.csv profile=poc status=FAIL severity=critical,high check=ssh limit=5
```

### Important: S3 cross-account verification
When analyzing **S3 findings**, always provide `external-profile` for a complete assessment. The external profile must be:
- An AWS account that is **NOT in the same AWS Organization** as the scanned account
- Used to simulate what any authenticated AWS user outside your org can access
- Without it, S3 findings may appear as false positives when they are actually accessible to external authenticated users

Example:
```
/analyze-fp file=output.csv profile=poc service=s3 external-profile=personal-aws
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
   The external-profile MUST be an AWS account NOT in the same AWS Organization. This is critical because S3 bucket policies and ACLs may grant access to "AuthenticatedUsers" (any valid AWS account) or use broad principal patterns that allow cross-org access.
   - `aws s3 ls s3://<bucket>/ --profile <external-profile> --no-sign-request` (anonymous/unauthenticated)
   - `aws s3 ls s3://<bucket>/ --profile <external-profile>` (authenticated as external out-of-org user)
   - `aws s3api head-object --bucket <bucket> --key <test-key> --profile <external-profile>` if listing succeeds (verify object-level read)
   - `aws s3api get-bucket-acl --bucket <bucket> --profile <external-profile>` (check if external user can read ACL)
   - Report clearly whether the external authenticated user could: list objects, read objects, read ACL
   - **If external-profile is NOT provided**: Print a prominent warning that S3 cross-account verification was skipped. Note that bucket policies granting access to `*` principal or `AuthenticatedUsers` cannot be fully validated without an external profile. Recommend the user re-run with `external-profile` for S3 findings.
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

#### Secrets Findings verification matrix:

Secrets findings require two layers of validation: (1) confirm the secret pattern is real and not a false pattern match, and (2) confirm the secret is still valid/active. Always approach in that order.

##### autoscaling_find_secrets_ec2_launch_configuration (ASG userdata secrets)

These are almost always Elastic Beanstalk (`awseb-` prefix) launch configurations that embed **temporary STS credentials** in userdata bootstrap scripts. These credentials are short-lived (typically 1–24 hours). The key question is: **was the launch config created recently enough that the credentials could still be valid?**

1. Get the launch configuration and its creation time:
   ```
   aws autoscaling describe-launch-configurations \
     --launch-configuration-names <name> \
     --profile <profile> --region <region> \
     --query 'LaunchConfigurations[0].{Created:CreatedTime,UserData:UserData}'
   ```
2. Base64-decode the UserData to inspect it:
   ```
   python -c "import base64,sys; print(base64.b64decode(sys.stdin.read()).decode('utf-8','ignore'))" <<< "<base64-userdata>"
   ```
   Or with AWS CLI output: pipe through `| python -c "import sys,base64; d=sys.stdin.read().strip(); print(base64.b64decode(d).decode('utf-8','ignore'))"`
3. Identify the secret type in the userdata:
   - Look for `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` — these are temporary STS credentials
   - Look for `aws configure` commands with embedded keys
   - Look for database passwords, API tokens, or other long-lived secrets
4. **Date-based verdict logic**:
   - Calculate age: `now - CreatedTime`
   - If the secret is an **STS temporary credential** (`AWS_SESSION_TOKEN` present) AND `CreatedTime` is **> 1 day ago** → **FALSE POSITIVE** (credential expired)
   - If the secret is an **STS temporary credential** AND `CreatedTime` is **< 1 day ago** → **TRUE POSITIVE** (may still be valid; should not be in userdata regardless)
   - If the secret is a **long-lived credential** (no session token, looks like an IAM access key) AND `CreatedTime` is any age → **TRUE POSITIVE** (long-lived keys in userdata are always a risk)
   - If the secret is a **database password or API token** → **TRUE POSITIVE** regardless of age (should be in Secrets Manager)
5. To confirm an IAM access key found in userdata is real vs expired, check:
   ```
   aws iam get-access-key-last-used --access-key-id <key-id> --profile <profile>
   ```
   If the key returns `NoSuchEntity` or shows as `Inactive` → **FALSE POSITIVE** (key deleted/deactivated).
6. **Verdict**: FALSE POSITIVE if all of: (a) secret is STS temporary cred, (b) launch config is > 1 day old, (c) no active key found. Otherwise TRUE POSITIVE.

##### awslambda_function_no_secrets_in_code (Lambda code secrets)

Prowler scans Lambda deployment packages for secret-like patterns. High false positive rate because variable names like `SECRET_KEY`, `api_key`, `password` trigger even when the value is a placeholder or env var reference.

1. Check what line and pattern was flagged:
   - The `STATUS_EXTENDED` field contains: `lambda_function.py: Secret Keyword on line 86`
   - Note the file name and line number
2. Check if the function still exists and is active:
   ```
   aws lambda get-function-configuration --function-name <name> --profile <profile> --region <region>
   ```
3. Get the function code to inspect the flagged line:
   ```
   aws lambda get-function --function-name <name> --profile <profile> --region <region> \
     --query 'Code.Location' --output text
   ```
   Then download and inspect: `curl -s "<presigned-url>" -o /tmp/fn.zip && unzip -p /tmp/fn.zip <filename> | sed -n '80,95p'`
4. **Verdict logic**:
   - If flagged line contains a hardcoded string value (not an env var lookup) AND the value looks like a real credential → **TRUE POSITIVE**
   - If flagged line is `secret = os.environ.get('SECRET_KEY')` or similar env var reference → **FALSE POSITIVE** (variable name triggered the pattern, not a real secret)
   - If flagged line is a comment, test fixture, or example string → **FALSE POSITIVE**
   - If the function no longer exists → **RESOURCE NOT FOUND**

##### awslambda_function_no_secrets_in_variables (Lambda environment variable secrets)

1. Get the actual environment variable values:
   ```
   aws lambda get-function-configuration --function-name <name> \
     --profile <profile> --region <region> \
     --query 'Environment.Variables'
   ```
2. Check the flagged variable name (e.g., `SLACK_WEBHOOK_URL`, `DB_PASSWORD`, `API_KEY`):
   - If the value is a real Slack webhook URL (`https://hooks.slack.com/...`) → **TRUE POSITIVE** (should be in Secrets Manager)
   - If the value is a real AWS access key format (`AKIA...`) → **TRUE POSITIVE** — also check with `aws iam get-access-key-last-used`
   - If the value is a placeholder like `changeme`, `<your-key-here>`, empty string → **FALSE POSITIVE**
   - If the value points to an SSM/Secrets Manager path (`/prod/db/password`) → **FALSE POSITIVE** (using secrets management correctly)
3. For webhook URLs and API tokens: attempt a lightweight validation call (e.g., a Slack ping) to confirm the token is still valid — do NOT send any actual messages or data. Just check if the auth returns 200 vs 401.

##### cloudformation_stack_outputs_find_secrets (CloudFormation output secrets)

CloudFormation stack outputs containing secrets is a critical finding — outputs are visible to anyone with `cloudformation:DescribeStacks` on the account.

1. Describe the stack and check the outputs:
   ```
   aws cloudformation describe-stacks --stack-name <name> \
     --profile <profile> --region <region> \
     --query 'Stacks[0].Outputs'
   ```
2. Identify the flagged output key and its value
3. Check if the value is a real AWS access key:
   ```
   aws iam get-access-key-last-used --access-key-id <key-id> --profile <profile>
   ```
4. **Verdict**: If the key is Active → **TRUE POSITIVE** (critical — exposed in CF output AND still valid). If Inactive/not found → **PARTIALLY TRUE** (was real, now expired).

##### iam_user_with_temporary_credentials (IAM users with broad long-lived credentials)

Note: despite the check name, this flags IAM users that have long-lived access keys with broad permissions — not temporary credentials. The name is misleading.

1. List all active access keys for the user:
   ```
   aws iam list-access-keys --user-name <user> --profile <profile>
   ```
2. Check creation date and status of each key
3. Check last used date:
   ```
   aws iam get-access-key-last-used --access-key-id <key-id> --profile <profile>
   ```
4. Check attached policies to understand the blast radius:
   ```
   aws iam list-attached-user-policies --user-name <user> --profile <profile>
   aws iam list-user-policies --user-name <user> --profile <profile>
   ```
5. **Verdict**: TRUE POSITIVE if the user has active long-lived keys with non-IAM/STS permissions. Note last-used date and creation date for context. Flag keys > 90 days old as higher priority.

##### iam_rotate_access_key_90_days (Keys not rotated in 90+ days)

1. List keys and check creation date:
   ```
   aws iam list-access-keys --user-name <user> --profile <profile>
   ```
2. Check if key is still active and last-used:
   ```
   aws iam get-access-key-last-used --access-key-id <key-id> --profile <profile>
   ```
3. **Verdict**: TRUE POSITIVE if key is Active AND CreateDate > 90 days ago. If key is Inactive → FALSE POSITIVE (already deactivated, Prowler may have scanned before deactivation).

##### iam_user_accesskey_unused (Unused access keys)

1. Check last-used date: `aws iam get-access-key-last-used --access-key-id <key-id> --profile <profile>`
2. **Verdict**: TRUE POSITIVE if key is Active AND has never been used (LastUsedDate = N/A) or not used in > 90 days. Recommend deactivating unused keys.

##### iam_user_two_active_access_key (Two active keys)

1. List both keys: `aws iam list-access-keys --user-name <user> --profile <profile>`
2. Check last-used for both — if one is unused, it's likely forgotten and should be deleted.
3. **Verdict**: TRUE POSITIVE if both keys are Active. Note if one is never used (higher risk).

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

**How an attacker could exploit this**:
- Provide 3-5 concrete examples of how an attacker could exploit the verified misconfiguration.
- Include example commands an attacker would use (e.g., ssh, curl, redis-cli, psql, kubectl, nc) to illustrate the attack surface.
- Cover: initial access, credential theft (e.g., IMDS), lateral movement, data exfiltration, and privilege escalation where applicable.
- Tailor examples to the specific resources attached (e.g., if RDS is attached, show database connection examples; if EKS nodes, show Kubelet API access).
- These are READ-ONLY illustrative examples for the human security team to evaluate. Do NOT execute any of these commands yourself.
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

### Step 5: Save report to file

After generating the full report (including all findings, attacker exploitation examples, summary table, and final counts), automatically save the complete report as **both a PDF and a markdown file** in the **same directory as the input CSV file**.

#### PDF report (primary output)

Use the **report template** in `templates/` directory of this repo (`prowler-claude-skills/templates/`). This ensures consistent formatting across all team members and service types.

**Required packages**: `pip install fpdf2 matplotlib`

- **Filename format**: `prowler-analysis-<ACCOUNT_UID>-<timestamp-from-csv-filename>.pdf`
  - Extract the account UID and timestamp from the input CSV filename (e.g., `prowler-output-331560656580-20260422065605.csv` -> `prowler-analysis-331560656580-20260422065605.pdf`)

##### How to use the template

Write a Python script (`.py` file) that imports and uses the template. The template lives at `prowler-claude-skills/templates/` and provides two classes:

- `ProwlerReport` — the PDF builder with all layout/styling built in
- `ChartGenerator` — generates dark-themed matplotlib charts as PNGs

**Script naming and location**:
- Save the script as `gen_report-<ACCOUNT_UID>-<timestamp>.py` in the **same directory as the input CSV file** (e.g., `gen_report-331560656580-20260422073611.py`)
- **DO NOT delete it after running** — the user may want to re-run it manually to regenerate the PDF without re-running the full analysis
- Execute it with `python <path>` to generate the PDF

**The script should add the template directory to sys.path, then follow this pattern:**

```python
import sys
sys.path.insert(0, r"<absolute-path-to-prowler-claude-skills>")  # parent of templates/
from templates import ProwlerReport, ChartGenerator

# 1. Generate charts
cg = ChartGenerator()
chart_paths = cg.generate_all(
    verdicts={"TRUE POSITIVE": 12, "FALSE POSITIVE": 5, "PARTIALLY TRUE": 2},
    risks={"CRITICAL": 2, "HIGH": 3, "MEDIUM": 7, "LOW": 6},
    exposure={"Truly Public": 12, "IP-Restricted": 5, "VPC-Only": 1},
    regions={"us-east-1": 16, "eu-west-1": 3},
)

# 2. Build report using high-level methods
report = ProwlerReport()
report.cover(title="Prowler S3 Analysis Report", subtitle="...", account_id="123456789012",
             metadata={"Date": "...", "Profile": "...", ...})
report.executive_summary(risk_posture="CRITICAL", summary_text="...",
    metrics={"Total\nFindings": 19, "True\nPositives": 12, ...},
    top_findings=["bucket-x: config leaked...", ...],
    warnings=[("Title", "Body text")])
report.charts_page(chart_paths)
report.summary_table(headers=["#","Resource","Verdict","Risk"], rows=[...], col_widths=[10,90,50,40])
report.findings_section("Critical & High Risk", [{"num":"1", "check":"...", "bucket":"...", "region":"...", "verdict":"TRUE POSITIVE", "risk":"CRITICAL", "policy":"...", "anon":"...", "ext":"...", "reason":"...", "rec":"...", "exploit":["..."]}])
report.findings_section_compact("Medium & Low Risk", [("2","bucket","region","MEDIUM","details","rec")])
report.false_positives_section([("3","bucket","region","IP-restricted")], explanation="...")
report.remediation_section([("IMMEDIATE","target","description"), ...])
report.save(r"<absolute-path-to-output.pdf>")
cg.cleanup()
```

See `templates/example_usage.py` for a complete working example.

##### Available ProwlerReport methods

| Method | Purpose |
|--------|---------|
| `cover(title, subtitle, account_id, metadata)` | Branded cover page with dark blue banner |
| `executive_summary(risk_posture, summary_text, metrics, top_findings, warnings)` | Exec summary with metric cards, top findings, warning boxes |
| `charts_page(chart_paths)` | 2x2 chart grid from ChartGenerator PNGs |
| `summary_table(headers, rows, col_widths)` | Findings summary table on new page |
| `findings_section(title, findings_list)` | Detailed finding cards with exploit examples |
| `findings_section_compact(title, compact_list)` | Compact cards for medium/low risk |
| `false_positives_section(fp_list, explanation)` | False positive section with explanation |
| `remediation_section(items)` | Priority-ordered remediation with colored badges |
| `save(path)` | Write PDF to disk |

Low-level helpers also available: `section_title()`, `subsection_title()`, `badge()`, `verdict_badge()`, `risk_badge()`, `verdict_risk_badges()`, `kv()`, `body_text()`, `bullet()`, `separator()`, `data_table()`, `warning_box()`, `safe_page_break()`.

##### ChartGenerator methods

| Method | Purpose |
|--------|---------|
| `generate_all(verdicts, risks, exposure, regions)` | Generate all 4 charts, returns dict of PNG paths |
| `donut(data, title, colors, filename)` | Single donut chart |
| `hbar(data, title, colors, filename)` | Single horizontal bar chart |
| `cleanup()` | Remove temp PNG files |

##### PDF page structure (in order)

1. **Cover page** — title banner, account ID, metadata
2. **Executive Summary** — risk posture badge, metric cards, top findings, warnings
3. **Charts page** — verdict donut, risk severity bars, exposure types, region distribution (2x2 grid)
4. **Findings Summary Table** — all findings at a glance
5. **Detailed Verdicts** — grouped by risk (CRITICAL first, then HIGH, MEDIUM, LOW)
6. **Priority Remediation** — ordered action items with priority badges

##### Important formatting notes

- The template handles all layout, colors, fonts, and page breaks automatically
- All key-value pairs use `set_xy()` positioning — no overflow issues
- `safe_page_break(need)` is called before every finding block — no clipping
- Charts use a consistent dark theme with white text
- Use `-` for bullets (not Unicode bullet char which causes encoding errors)
- The title in `cover()` should reflect the service: "Prowler S3 Analysis Report", "Prowler EC2 Analysis Report", etc.

#### Markdown report (secondary output)

Also save a markdown version for easy viewing in terminals/editors.

- **Filename format**: `prowler-analysis-<ACCOUNT_UID>-<timestamp-from-csv-filename>.md`
- **File contents**: The full report including:
  - Report metadata header (source CSV, account, profile, filters, date)
  - Executive summary paragraph
  - Filtered findings summary table
  - All detailed finding verdicts with attacker exploitation examples
  - Summary table and final counts
  - Key observations and priority remediation order
- Inform the user of all saved file paths after writing: the PDF, the markdown file, and the `gen_report-*.py` script.

## Important notes

- Always use `--profile` and `--region` flags on every AWS CLI call.
- If a resource is not found (terminated/deleted), mark as "RESOURCE NOT FOUND - likely terminated since scan" and note it may have been a true positive at scan time.
- For EC2 port exposure findings, ALWAYS check all 4 layers: Security Group, NACL, Route Table (IGW), and Public IP.
- For S3, ALWAYS try both authenticated (org account) AND unauthenticated access if possible.
- Rate limit yourself: add brief pauses between API calls if you're making many calls.
- If you encounter AccessDenied on any check, note it in the report and explain what permission is missing.
- Group similar findings (e.g., same SG flagged multiple times) and verify once, apply verdict to all.
- Parse the CSV using Python with the csv module since the fields contain semicolons, newlines, and complex content.
