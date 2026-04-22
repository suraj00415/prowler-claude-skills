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
| `external-profile` | AWS profile from a **different AWS organization** (not same org) for cross-account S3/snapshot/AMI testing. **Strongly recommended for S3 findings.** | None (skipped with warning) |
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

### S3 with cross-account verification (strongly recommended for S3)
```
/analyze-fp file=prowler-output.csv profile=poc service=s3 external-profile=external-pentest
```
This will:
- Check bucket policies, ACLs, and public access blocks using your profile
- Test **anonymous/unauthenticated** access via curl
- Test **authenticated cross-account** access using the external profile

> **Why `external-profile` matters for S3**: A bucket may appear locked down from within your AWS Organization, but S3 bucket policies can grant access to `*` (any principal) or `AuthenticatedUsers` (any valid AWS account). The only way to verify this is by attempting access from an account **outside your AWS Organization**. Without it, the analysis may miss buckets that are accessible to any authenticated AWS user on the internet.

#### Requirements for the external profile
- Must be an AWS account that is **NOT in the same AWS Organization** as the scanned account
- Only needs `s3:ListBucket`, `s3:GetObject`, and `s3:GetBucketAcl` permissions (these are tested against the target, not granted by IAM)
- A personal AWS account or a dedicated pentesting account works well
- If not provided, S3 findings will include a warning that cross-account verification was skipped

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

## Tips to minimize `/analyze-fp` workload

| Tip | Why it helps |
|-----|-------------|
| Always use `--status FAIL` | Skips ~70-80% of findings (PASS results don't need FP analysis) |
| Use `--severity critical high` | Focuses on actionable items, skips low/informational noise |
| Scope with `--service` | A full scan produces 26,000+ findings; scoping to 2-3 services drops it to hundreds |
| Use `--output-filename` | Name files by purpose so you can easily reference them in `/analyze-fp` |
| Use `--region` if you know where your infra lives | Avoids scanning 30+ empty regions |
| Use `--mutelist-file` for known exceptions | Prevents re-analyzing findings you've already accepted |
| Run separate scans per focus area | e.g., one for network, one for IAM, one for data - easier to analyze in batches |
