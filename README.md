# Prowler Finding Analyzer

A Claude Code custom slash command that automatically cross-verifies Prowler security findings against your live AWS environment using read-only API calls to determine if findings are true positives or false positives.

## Prerequisites

- [Claude Code](https://claude.ai/claude-code) CLI or IDE extension installed
- AWS CLI configured with named profiles
- Prowler CSV output file (generated with default semicolon-delimited format)

## Setup

1. Clone or copy this directory so that `.claude/commands/analyze-fp.md` and `CLAUDE.md` are in your working directory.
2. Open the directory in Claude Code.
3. The `/analyze-fp` slash command will be available automatically.

## Usage

```
/analyze-fp file=<csv_file> profile=<aws_profile> [service=<svc>] [status=<status>] [severity=<sev>] [check=<pattern>] [external-profile=<profile>] [limit=<n>] [region=<region>]
```

### Required arguments

| Argument | Description |
|----------|-------------|
| `file` | Path to the Prowler CSV output file. Can be absolute or relative to `prowler-output/` directory |
| `profile` | AWS CLI profile name to use for verification (must have read permissions) |

### Optional arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `service` | AWS service(s) to filter. **Comma-separated for multiple** | All services |
| `status` | Finding status: `FAIL` or `PASS` | `FAIL` |
| `severity` | Severity level(s). **Comma-separated for multiple** | `critical,high` |
| `check` | CHECK_ID pattern filter (partial match supported) | None |
| `external-profile` | AWS profile from a **different AWS organization** for cross-account testing | None (skipped) |
| `limit` | Max findings to analyze in detail. Use `all` for unlimited | `10` |
| `region` | Override AWS region for all CLI calls | Region from finding |

## Examples

### Basic - analyze all critical/high failures
```
/analyze-fp file=prowler-output.csv profile=poc
```

### Single service filter
```
/analyze-fp file=prowler-output.csv profile=poc service=ec2
```

### Multiple services
```
/analyze-fp file=prowler-output.csv profile=poc service=ec2,s3,iam
```

### Multiple severities
```
/analyze-fp file=prowler-output.csv profile=poc severity=critical,high,medium
```

### Specific check pattern
```
/analyze-fp file=prowler-output.csv profile=poc check=ssh limit=5
```

### S3 with cross-account verification
```
/analyze-fp file=prowler-output.csv profile=poc service=s3 external-profile=external-pentest
```
This will:
- Check bucket policies, ACLs, and public access blocks using your profile
- Test **anonymous/unauthenticated** access via curl
- Test **authenticated cross-account** access using the external profile (should be an AWS account NOT in your organization)

### Combined filters
```
/analyze-fp file=prowler-output.csv profile=poc service=ec2,s3 status=FAIL severity=critical check=public limit=20
```

## What it verifies

### EC2
| Check type | Verification layers |
|------------|-------------------|
| Port exposure (SSH, RDP, etc.) | Security Group rules + Network ACLs + Route table (IGW) + Public IP |
| Security Groups | Rule existence + whether SG is attached to any running resource |
| Public IP | Instance state + subnet routing + SG exposure |
| EBS encryption | Volume/snapshot encryption status |
| Public snapshots | Snapshot `createVolumePermission` attribute |
| Public AMIs | AMI `launchPermission` attribute + external account visibility |
| IMDSv2 | Instance `MetadataOptions.HttpTokens` setting |

### S3
| Check type | Verification method |
|------------|-------------------|
| Public access | Bucket public access block + ACL + bucket policy analysis |
| Anonymous access | HTTP curl to bucket endpoint (unauthenticated) |
| Cross-account access | `aws s3 ls` and `get-object` with external profile |
| Account-level block | `s3control get-public-access-block` |
| Encryption | `get-bucket-encryption` |

### IAM
| Check type | Verification method |
|------------|-------------------|
| Overly permissive policies | Policy document analysis |
| Unused credentials | Access key last used, credential report |
| MFA | `list-mfa-devices` |

### RDS
| Check type | Verification method |
|------------|-------------------|
| Public access | `PubliclyAccessible` flag + SG rules + subnet routing |
| Encryption | `StorageEncrypted` attribute |

## Output format

Each finding produces a structured verdict:

```
---
### Finding: ec2_instance_port_ssh_exposed_to_internet
Resource: arn:aws:ec2:us-east-1:123456789012:instance/i-0abc123
Region: us-east-1
Severity: critical
Prowler Says: Instance has SSH exposed to 0.0.0.0/0

Verification Steps Performed:
1. Instance state: running, Public IP: 54.x.x.x
2. SG sg-0abc123: port 22 open to 0.0.0.0/0
3. Subnet route table: IGW igw-abc123 present
4. NACL: no deny rules on port 22

Verdict: TRUE POSITIVE
Confidence: HIGH
Reason: All 4 layers confirm SSH is internet-reachable
Risk Level: CRITICAL
Recommendation: Restrict SG to corporate CIDR or use SSM Session Manager
---
```

Final summary table shows all findings at a glance with pass/fail counts.

## Safety

This tool operates in **read-only mode**. It will:
- Only use AWS `describe-*`, `get-*`, `list-*`, and `head-*` API calls
- Never create, modify, or delete any AWS resource
- Never execute remediation commands (only suggests them)
- Present remediation as recommendations for manual review

See [CLAUDE.md](.claude/CLAUDE.md) for the complete safety rules and API allowlist/blocklist.

## Running Prowler effectively

The more you pre-filter at scan time, the less work `/analyze-fp` has to do. Use these flags to produce focused, smaller CSV outputs.

### Key flags to reduce noise

#### 1. `--status` - Only export failures (most important flag)

By default Prowler exports PASS + FAIL + MANUAL. Export only what you need:

```bash
# Only failures - dramatically reduces CSV size
--status FAIL

# Failures + manual checks that need human review
--status FAIL MANUAL
```

#### 2. `--service` / `--services` - Scope to specific services

Scan only the services you care about instead of all ~60+ services:

```bash
# Single service
--service ec2

# Multiple services (space-separated)
--service ec2 s3 iam rds lambda

# Common groupings:
# Network exposure:   --service ec2 elb elbv2 rds
# Data security:      --service s3 ebs rds dynamodb
# Identity:           --service iam accessanalyzer sso
# Logging:            --service cloudtrail cloudwatch
```

#### 3. `--severity` / `--severities` - Focus on what matters

Skip low/informational findings and focus on actionable items:

```bash
# Critical and high only
--severity critical high

# Critical, high, and medium
--severity critical high medium
```

#### 4. `--output-directory` and `--output-filename` - Organize scan outputs

Separate scans into meaningful folders and names so you can reference them easily:

```bash
# Custom output directory
--output-directory /home/prowler/output/2026-04-22

# Custom filename (without extension)
--output-filename ec2-critical-fails

# Both together
--output-directory /home/prowler/output/weekly-scans \
--output-filename ec2-s3-critical-2026-04-22
```

#### 5. `--region` - Limit to specific regions

Avoid scanning all regions if your infra is only in a few:

```bash
# Single region
--region us-east-1

# Multiple regions
--region us-east-1 us-west-2 eu-west-1
```

#### 6. `--check` / `--checks` - Run specific checks only

If you already know which checks you want to verify:

```bash
# Specific checks
--check ec2_instance_port_ssh_exposed_to_internet ec2_instance_port_rdp_exposed_to_internet

# List available checks first
prowler aws --list-checks
```

#### 7. `--compliance` - Scan against a specific framework

Run only the checks required by a compliance framework:

```bash
--compliance cis_6.0_aws
--compliance soc2_aws
--compliance hipaa_aws
--compliance pci_4.0_aws
--compliance nist_800_53_revision_5_aws
```

#### 8. `--excluded-service` / `--excluded-check` - Skip what you don't need

```bash
# Skip services you've already reviewed
--excluded-service cloudwatch guardduty

# Skip specific checks that are known exceptions
--excluded-check ec2_instance_older_than_specific_days ec2_instance_detailed_monitoring_enabled
```

#### 9. `--resource-tag` / `--resource-arn` - Target specific resources

```bash
# Only scan resources with a specific tag
--resource-tag env=production

# Only scan specific resource ARNs
--resource-arn arn:aws:ec2:us-east-1:123456789012:instance/i-0abc123
```

#### 10. `--mutelist-file` - Suppress known exceptions

Create a YAML mutelist for findings you've already reviewed and accepted:

```bash
--mutelist-file /home/prowler/.aws/prowler-mutelist.yaml
```

### Recommended scan recipes

#### Quick critical-only scan for FP analysis
```bash
prowler aws \
  --profile <profile> \
  --status FAIL \
  --severity critical high \
  --service ec2 s3 iam rds \
  --output-directory prowler-output/fp-analysis \
  --output-filename critical-high-fails \
  -M csv \
  --no-banner
```
Then analyze with:
```
/analyze-fp file=fp-analysis/critical-high-fails.csv profile=<profile>
```

#### Network exposure audit
```bash
prowler aws \
  --profile <profile> \
  --status FAIL \
  --severity critical high \
  --service ec2 elb elbv2 rds \
  --region us-east-1 \
  --output-directory prowler-output/network-audit \
  --output-filename network-exposure \
  -M csv \
  --no-banner
```
Then analyze with:
```
/analyze-fp file=network-audit/network-exposure.csv profile=<profile> service=ec2 check=exposed limit=20
```

#### S3 bucket security audit with cross-account testing
```bash
prowler aws \
  --profile <profile> \
  --status FAIL \
  --service s3 \
  --output-directory prowler-output/s3-audit \
  --output-filename s3-public-checks \
  -M csv \
  --no-banner
```
Then analyze with:
```
/analyze-fp file=s3-audit/s3-public-checks.csv profile=<profile> service=s3 external-profile=<external-profile>
```

#### Compliance scan (e.g., CIS AWS 6.0)
```bash
prowler aws \
  --profile <profile> \
  --status FAIL \
  --compliance cis_6.0_aws \
  --output-directory prowler-output/compliance \
  --output-filename cis6-failures \
  -M csv \
  --no-banner
```

### Tips to minimize `/analyze-fp` workload

| Tip | Why it helps |
|-----|-------------|
| Always use `--status FAIL` | Skips ~70-80% of findings (PASS results don't need FP analysis) |
| Use `--severity critical high` | Focuses on actionable items, skips low/informational noise |
| Scope with `--service` | A full scan produces 26,000+ findings; scoping to 2-3 services drops it to hundreds |
| Use `--output-filename` | Name files by purpose so you can easily reference them in `/analyze-fp` |
| Use `--region` if you know where your infra lives | Avoids scanning 30+ empty regions |
| Use `--mutelist-file` for known exceptions | Prevents re-analyzing findings you've already accepted |
| Run separate scans per focus area | e.g., one for network, one for IAM, one for data - easier to analyze in batches |
