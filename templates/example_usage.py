"""
Example: How to use the Prowler report template.

This shows the full API for generating a report.
Claude uses this as a reference when building reports via /analyze-fp.
Teammates can also run this directly or adapt it.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from templates import ProwlerReport, ChartGenerator


# ── 1. Prepare your data ────────────────────────────────────────────────

# Verdicts / risk counts (from your analysis)
verdicts = {"TRUE POSITIVE": 12, "FALSE POSITIVE": 5, "PARTIALLY TRUE": 2}
risks    = {"CRITICAL": 2, "HIGH": 3, "MEDIUM": 7, "LOW": 6}
exposure = {"Truly Public\n(no IP restriction)": 12, "IP-Restricted\n(corporate IPs)": 5, "VPC IP-Restricted": 1}
regions  = {"us-east-1": 16, "eu-west-1": 3}

# Detailed findings - critical/high
findings_critical = [
    {
        "num": "1",
        "check": "s3_bucket_public_access",
        "bucket": "my-config-bucket",
        "region": "us-east-1",
        "verdict": "TRUE POSITIVE",
        "risk": "CRITICAL",
        "policy": 'Principal:"*" with s3:GetObject. No IP condition.',
        "anon": "SUCCESS - config.json (50KB)",
        "ext": "SUCCESS",
        "reason": "Live config files anonymously readable on the internet.",
        "rec": "Add public access block immediately. Rotate any exposed secrets.",
        "exploit": [
            "curl https://my-config-bucket.s3.amazonaws.com/config.json",
            "Extract API keys, DB connection strings from config",
            "Map internal architecture from environment files",
        ],
    },
    # ... add more findings
]

# Medium/low findings (compact format)
findings_medium = [
    ("2", "my-assets-bucket", "us-east-1", "MEDIUM",
     "JS bundles publicly readable. Anon: SUCCESS.", "Use CloudFront OAC."),
]

# False positives
findings_fp = [
    ("3", "my-internal-bucket", "us-east-1", "IP-restricted to 10.0.0.0/8"),
]

# Summary table rows
summary_rows = [
    ["1", "my-config-bucket", "TRUE POSITIVE", "CRITICAL"],
    ["2", "my-assets-bucket", "TRUE POSITIVE", "MEDIUM"],
    ["3", "my-internal-bucket", "FALSE POSITIVE", "LOW"],
]

# Remediation items: (priority, target, description)
remediation = [
    ("IMMEDIATE", "my-config-bucket", "Config files publicly readable. Add PAB, rotate secrets."),
    ("HIGH", "Account-Level PAB", "Enable all 4 settings to prevent future misconfigurations."),
    ("MEDIUM", "my-assets-bucket", "Add CloudFront OAC instead of direct S3 public access."),
    ("LOW", "my-internal-bucket", "Replace Principal:* with IAM principals for defense-in-depth."),
]


# ── 2. Generate charts ──────────────────────────────────────────────────

cg = ChartGenerator()
chart_paths = cg.generate_all(
    verdicts=verdicts,
    risks=risks,
    exposure=exposure,
    regions=regions,
)


# ── 3. Build the PDF ────────────────────────────────────────────────────

report = ProwlerReport()

# Cover page
report.cover(
    title="Prowler S3 Analysis Report",
    subtitle="Security Finding Verification & Risk Assessment",
    account_id="123456789012",
    metadata={
        "Date": "2026-04-23",
        "Profile": "my-profile",
        "External Profile": "ext-profile (out-of-org)",
        "Filters": "service=s3, status=FAIL, severity=critical,high",
        "Source": "prowler-output-123456789012-20260423120000.csv",
    },
)

# Executive summary
report.executive_summary(
    risk_posture="CRITICAL",
    summary_text=(
        "12 of 19 findings confirmed as true positives. "
        "1 CRITICAL bucket contains live config files readable from the internet. "
        "Account-level S3 public access block is disabled."
    ),
    metrics={
        "Total\nFindings": 19,
        "True\nPositives": 12,
        "False\nPositives": 5,
        "Partially\nTrue": 2,
    },
    top_findings=[
        "my-config-bucket: 50KB config.json anonymously readable with API keys",
    ],
    warnings=[
        (
            "Account-Level S3 Public Access Block is DISABLED",
            "All 4 settings (BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, "
            "RestrictPublicBuckets) are OFF.",
        ),
    ],
)

# Charts page
report.charts_page(chart_paths)

# Summary table
report.summary_table(
    headers=["#", "Resource", "Verdict", "Risk"],
    rows=summary_rows,
    col_widths=[10, 90, 50, 40],
)

# Detailed findings
report.findings_section("Critical & High Risk", findings_critical)
report.findings_section_compact("Medium & Low Risk", findings_medium)
report.false_positives_section(
    findings_fp,
    explanation='These buckets use Principal:"*" but IP conditions block external access.',
)

# Remediation
report.remediation_section(remediation)

# Save
output_path = report.save("example-report.pdf")
print(f"Report saved: {output_path}")

# Cleanup chart temp files
cg.cleanup()
