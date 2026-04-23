"""
Prowler Analysis PDF Report Template.

Provides a consistent, professional PDF layout for all Prowler finding
analysis reports regardless of service type (S3, EC2, IAM, RDS, etc.).

Usage:
    from templates import ProwlerReport, ChartGenerator

    report = ProwlerReport()

    # 1. Cover page
    report.cover(
        title="Prowler S3 Analysis Report",
        subtitle="Security Finding Verification & Risk Assessment",
        account_id="331560656580",
        metadata={
            "Date": "2026-04-22",
            "Profile": "poc",
            "External Profile": "thm (out-of-org)",
            "Filters": "service=s3, status=FAIL, severity=critical,high",
            "Source": "prowler-output-331560656580-20260422073611.csv",
        },
    )

    # 2. Executive summary
    report.executive_summary(
        risk_posture="CRITICAL",
        summary_text="12 of 19 findings confirmed as true positives ...",
        metrics={"Total Findings": 19, "True Positives": 12, ...},
        top_findings=["tt-config-useast1-int: 98KB config ...", ...],
        warnings=["Account-Level S3 Public Access Block is COMPLETELY DISABLED"],
    )

    # 3. Charts
    cg = ChartGenerator()
    chart_paths = cg.generate_all(verdicts={...}, risks={...}, ...)
    report.charts_page(chart_paths)
    cg.cleanup()

    # 4. Summary table
    report.summary_table(headers, rows, col_widths)

    # 5. Detailed findings
    report.findings_section("Critical & High Risk", findings_list)
    report.findings_section_compact("Medium & Low Risk", compact_list)
    report.false_positives_section(fp_list, explanation)

    # 6. Remediation
    report.remediation_section(remediation_list)

    # 7. Save
    report.save("output.pdf")
"""

from fpdf import FPDF


# ── Color palettes ───────────────────────────────────────────────────────
BRAND_DARK = (0, 51, 102)      # dark navy - headers, title bar
BRAND_LIGHT = (245, 245, 250)  # light gray - alt rows
TEXT_DARK = (33, 37, 41)       # near-black body text
TEXT_MUTED = (80, 80, 80)      # labels / secondary text
WHITE = (255, 255, 255)
HEADER_BG = (33, 37, 41)       # table headers

VERDICT_COLORS = {
    "TRUE POSITIVE": (180, 0, 0),
    "FALSE POSITIVE": (40, 167, 69),
    "PARTIALLY TRUE": (220, 80, 0),
}
RISK_COLORS = {
    "CRITICAL": (180, 0, 0),
    "HIGH": (220, 80, 0),
    "MEDIUM": (180, 140, 0),
    "LOW": (40, 167, 69),
    "INFORMATIONAL": (100, 100, 100),
}
PRIORITY_COLORS = {
    "IMMEDIATE": (180, 0, 0),
    "URGENT": (220, 80, 0),
    "HIGH": (200, 100, 0),
    "MEDIUM": (180, 140, 0),
    "LOW": (40, 167, 69),
}
WARNING_BG = (255, 243, 205)
WARNING_BORDER = (255, 193, 7)
WARNING_TEXT = (133, 100, 4)


class ProwlerReport(FPDF):
    """Reusable PDF report for Prowler analysis results."""

    def __init__(self):
        super().__init__()
        self.alias_nb_pages()
        self.set_auto_page_break(auto=True, margin=18)
        self._on_cover = False

    # ── FPDF overrides ───────────────────────────────────────────────────

    def header(self):
        if self._on_cover:
            return
        self.set_font("Helvetica", "I", 7)
        self.set_text_color(*TEXT_MUTED)
        self.cell(0, 5, self._header_text, align="R", new_x="LMARGIN", new_y="NEXT")
        self.ln(1)

    def footer(self):
        self.set_y(-12)
        self.set_font("Helvetica", "I", 7)
        self.set_text_color(150, 150, 150)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")

    # ── Primitive building blocks ────────────────────────────────────────

    def _set_text(self, r=0, g=0, b=0):
        self.set_text_color(r, g, b)

    def section_title(self, title):
        """Large blue section header with underline."""
        self.set_font("Helvetica", "B", 13)
        self._set_text(*BRAND_DARK)
        self.cell(0, 9, title, new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(*BRAND_DARK)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(4)

    def subsection_title(self, title):
        """Bold black subsection header."""
        self.set_font("Helvetica", "B", 10)
        self._set_text(*TEXT_DARK)
        self.multi_cell(0, 6, title, new_x="LMARGIN", new_y="NEXT")
        self.ln(1)

    def badge(self, text, r, g, b):
        """Colored pill badge (inline, does not break line)."""
        self.set_font("Helvetica", "B", 8)
        self.set_fill_color(r, g, b)
        self._set_text(255, 255, 255)
        w = self.get_string_width(f" {text} ") + 6
        self.cell(w, 5.5, f" {text} ", fill=True)
        self.cell(2, 5.5, "")

    def verdict_badge(self, verdict):
        """Verdict-colored badge."""
        r, g, b = VERDICT_COLORS.get(verdict, (0, 0, 0))
        self.badge(verdict, r, g, b)

    def risk_badge(self, risk):
        """Risk-colored badge."""
        r, g, b = RISK_COLORS.get(risk, (0, 0, 0))
        self.badge(risk, r, g, b)

    def verdict_risk_badges(self, verdict, risk):
        """Verdict + Risk badges on one line."""
        self.verdict_badge(verdict)
        self.risk_badge(risk)
        self._set_text(0, 0, 0)
        self.ln(7)

    def kv(self, key, value):
        """Key-value row. Key right-aligned in fixed column, value wraps."""
        KW = 42
        VW = self.w - self.l_margin - self.r_margin - KW - 2
        y = self.get_y()
        self.set_xy(self.l_margin, y)
        self.set_font("Helvetica", "B", 8.5)
        self._set_text(*TEXT_MUTED)
        self.cell(KW, 5, key + ":", align="R")
        self.set_xy(self.l_margin + KW + 2, y)
        self.set_font("Helvetica", "", 8.5)
        self._set_text(*TEXT_DARK)
        self.multi_cell(VW, 5, str(value), new_x="LMARGIN", new_y="NEXT")

    def body_text(self, text):
        """Normal paragraph text."""
        self.set_font("Helvetica", "", 8.5)
        self._set_text(*TEXT_DARK)
        self.multi_cell(0, 5, text, new_x="LMARGIN", new_y="NEXT")
        self.ln(1)

    def bullet(self, text):
        """Indented dash-bullet item."""
        self.set_font("Helvetica", "", 8)
        self._set_text(*TEXT_DARK)
        x0 = self.l_margin + 6
        self.set_x(x0)
        self.cell(4, 4.5, "-")
        bw = self.w - self.get_x() - self.r_margin
        self.multi_cell(bw, 4.5, text, new_x="LMARGIN", new_y="NEXT")

    def separator(self):
        """Light gray horizontal rule."""
        self.set_draw_color(220, 220, 220)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(4)

    def data_table(self, headers, rows, col_widths=None):
        """Table with dark header and alternating row shading."""
        if col_widths is None:
            usable = self.w - self.l_margin - self.r_margin
            col_widths = [usable / len(headers)] * len(headers)
        # Header row
        self.set_font("Helvetica", "B", 7.5)
        self.set_fill_color(*HEADER_BG)
        self._set_text(255, 255, 255)
        for i, h in enumerate(headers):
            self.cell(col_widths[i], 6, h, border=1, fill=True, align="C")
        self.ln()
        # Data rows
        self.set_font("Helvetica", "", 7)
        self._set_text(0, 0, 0)
        for ri, row in enumerate(rows):
            if self.get_y() > 270:
                self.add_page()
            fill = ri % 2 == 0
            if fill:
                self.set_fill_color(*BRAND_LIGHT)
            for i, cell_val in enumerate(row):
                al = "C" if i != 1 else "L"
                self.cell(col_widths[i], 5, str(cell_val), border=1, fill=fill, align=al)
            self.ln()

    def warning_box(self, title, body):
        """Yellow warning callout box."""
        y0 = self.get_y()
        # Calculate height needed
        self.set_font("Helvetica", "", 8)
        lines = len(body) // 90 + 2  # rough estimate
        box_h = 10 + lines * 5
        self.set_fill_color(*WARNING_BG)
        self.set_draw_color(*WARNING_BORDER)
        self.rect(self.l_margin, y0, self.w - self.l_margin - self.r_margin, box_h, "DF")
        self.set_xy(self.l_margin + 3, y0 + 2)
        self.set_font("Helvetica", "B", 9)
        self._set_text(*WARNING_TEXT)
        self.cell(0, 5, title, new_x="LMARGIN", new_y="NEXT")
        self.set_x(self.l_margin + 3)
        self.set_font("Helvetica", "", 8)
        self.multi_cell(
            self.w - self.l_margin - self.r_margin - 6, 4.5, body,
            new_x="LMARGIN", new_y="NEXT",
        )
        self.set_y(y0 + box_h + 3)

    def safe_page_break(self, need=50):
        """Add page if remaining space is less than `need` mm."""
        if self.get_y() > 297 - 18 - need:
            self.add_page()

    # ── High-level page builders ─────────────────────────────────────────

    def cover(self, title, subtitle, account_id, metadata=None):
        """Render a branded cover page.

        Args:
            title:      Main report title (e.g., "Prowler S3 Analysis Report")
            subtitle:   Tagline below title
            account_id: AWS account ID (used in header text for subsequent pages)
            metadata:   dict of key-value pairs shown below the title banner
        """
        self._header_text = f"Prowler Analysis - Account {account_id}"
        self._on_cover = True
        self.add_page()
        self.ln(30)

        # Title banner
        self.set_fill_color(*BRAND_DARK)
        self.rect(0, 55, 210, 50, "F")
        self.set_xy(10, 60)
        self.set_font("Helvetica", "B", 28)
        self._set_text(255, 255, 255)
        self.cell(190, 14, title, align="C", new_x="LMARGIN", new_y="NEXT")
        self.set_font("Helvetica", "", 14)
        self.cell(190, 10, f"AWS Account {account_id}", align="C", new_x="LMARGIN", new_y="NEXT")
        self.set_font("Helvetica", "I", 10)
        self.cell(190, 8, subtitle, align="C", new_x="LMARGIN", new_y="NEXT")

        # Metadata
        if metadata:
            self.set_y(120)
            self._set_text(*TEXT_DARK)
            for k, v in metadata.items():
                self.kv(k, v)
                self.ln(1)

        self._on_cover = False

    def executive_summary(
        self, risk_posture, summary_text, metrics, top_findings=None, warnings=None
    ):
        """Render the executive summary page.

        Args:
            risk_posture: One of CRITICAL / HIGH / MEDIUM / LOW
            summary_text: 2-3 sentence overview paragraph
            metrics:      dict like {"Total Findings": 19, "True Positives": 12, ...}
                          First 4 entries are rendered as big colored cards.
            top_findings: list of one-liner strings for top critical findings
            warnings:     list of warning strings (each rendered as a yellow box)
        """
        self.add_page()
        self.section_title("Executive Summary")

        # Risk posture
        self.set_font("Helvetica", "B", 9)
        self._set_text(*TEXT_MUTED)
        self.cell(42, 8, "Risk Posture:", align="R")
        self.cell(3, 8, "")
        r, g, b = RISK_COLORS.get(risk_posture, (0, 0, 0))
        self.set_fill_color(r, g, b)
        self._set_text(255, 255, 255)
        self.set_font("Helvetica", "B", 14)
        self.cell(35, 8, f" {risk_posture} ", fill=True, new_x="LMARGIN", new_y="NEXT")
        self._set_text(0, 0, 0)
        self.ln(4)

        # Summary paragraph
        self.body_text(summary_text)
        self.ln(2)

        # Metric cards
        CARD_COLORS = [
            TEXT_DARK,                          # total - dark
            VERDICT_COLORS["TRUE POSITIVE"],    # TP - red
            VERDICT_COLORS["FALSE POSITIVE"],   # FP - green
            VERDICT_COLORS["PARTIALLY TRUE"],   # PT - orange
        ]
        items = list(metrics.items())[:4]
        card_w = 42
        card_gap = 4
        start_x = (210 - (card_w * len(items) + card_gap * (len(items) - 1))) / 2
        y0 = self.get_y()
        for i, ((label, num), color) in enumerate(zip(items, CARD_COLORS)):
            x = start_x + i * (card_w + card_gap)
            self.set_fill_color(*color)
            self.rect(x, y0, card_w, 28, "F")
            self.set_xy(x, y0 + 2)
            self.set_font("Helvetica", "B", 24)
            self._set_text(255, 255, 255)
            self.cell(card_w, 14, str(num), align="C")
            self.set_xy(x, y0 + 16)
            self.set_font("Helvetica", "", 8)
            # Replace spaces with newlines for wrapping
            self.multi_cell(card_w, 4, label, align="C")
        self.set_y(y0 + 34)
        self._set_text(0, 0, 0)
        self.ln(2)

        # Top findings
        if top_findings:
            self.set_font("Helvetica", "B", 10)
            self._set_text(*BRAND_DARK)
            self.cell(0, 7, f"Top {len(top_findings)} Critical Findings", new_x="LMARGIN", new_y="NEXT")
            self._set_text(*TEXT_DARK)
            for t in top_findings:
                self.bullet(t)
            self.ln(3)

        # Warnings
        if warnings:
            for w in warnings:
                if isinstance(w, tuple):
                    self.warning_box(w[0], w[1])
                elif isinstance(w, str):
                    self.warning_box("WARNING", w)

    def charts_page(self, chart_paths, chart_width=92, chart_height=72, gap=6):
        """Embed chart images in a 2x2 grid layout.

        Args:
            chart_paths: dict with keys like "verdict", "risk", "exposure", "region"
                         and values as PNG file paths. Up to 4 charts.
            chart_width:  width in mm for each chart image
            chart_height: height in mm for each chart image
            gap:          horizontal gap between columns
        """
        self.add_page()
        self.section_title("Visual Analysis")

        paths = list(chart_paths.values())
        x1 = self.l_margin
        x2 = self.l_margin + chart_width + gap
        y_top = self.get_y()

        if len(paths) > 0:
            self.image(paths[0], x=x1, y=y_top, w=chart_width)
        if len(paths) > 1:
            self.image(paths[1], x=x2, y=y_top, w=chart_width)

        y_mid = y_top + chart_height + 4
        if len(paths) > 2:
            self.image(paths[2], x=x1, y=y_mid, w=chart_width)
        if len(paths) > 3:
            self.image(paths[3], x=x2, y=y_mid, w=chart_width)

        self.set_y(y_mid + chart_height + 6)

    def summary_table(self, headers, rows, col_widths=None):
        """Render the findings summary table on a new page."""
        self.add_page()
        self.section_title("Findings Summary")
        self.data_table(headers, rows, col_widths)
        self.ln(6)

    def findings_section(self, title, findings):
        """Render detailed finding cards.

        Args:
            title: Section title (e.g., "Critical & High Risk")
            findings: list of dicts, each with keys:
                num, check, bucket, region, verdict, risk,
                policy, anon, ext, reason, rec, exploit (list of strings)
        """
        self.add_page()
        self.section_title(f"Detailed Verdicts - {title}")

        for f in findings:
            self.safe_page_break(70)
            self.subsection_title(f"Finding #{f['num']}: {f['check']}")
            self.verdict_risk_badges(f["verdict"], f["risk"])
            self.kv("Bucket", f"{f['bucket']} ({f['region']})")
            if f.get("policy"):
                self.kv("Policy", f["policy"])
            if f.get("anon"):
                self.kv("Anon Test", f["anon"])
            if f.get("ext"):
                self.kv("External Test", f["ext"])
            self.kv("Reason", f["reason"])
            self.kv("Recommendation", f["rec"])
            if f.get("exploit"):
                self.ln(1)
                self.set_font("Helvetica", "B", 8.5)
                self._set_text(*TEXT_MUTED)
                self.set_x(self.l_margin + 4)
                self.cell(0, 5, "Exploitation examples:", new_x="LMARGIN", new_y="NEXT")
                for e in f["exploit"]:
                    self.safe_page_break(10)
                    self.bullet(e)
            self.ln(3)
            self.separator()

    def findings_section_compact(self, title, findings):
        """Render compact finding cards for medium/low risk.

        Args:
            title: Section title
            findings: list of tuples:
                (num, bucket, region, risk, details, recommendation)
        """
        self.safe_page_break(60)
        self.section_title(f"Detailed Verdicts - {title}")
        for num, bucket, region, risk, details, rec in findings:
            self.safe_page_break(35)
            self.verdict_risk_badges("TRUE POSITIVE", risk)
            self.kv("Finding #", str(num))
            self.kv("Bucket", f"{bucket} ({region})")
            self.kv("Details", details)
            self.kv("Recommendation", rec)
            self.ln(2)
            self.separator()

    def false_positives_section(self, findings, explanation=""):
        """Render false positive findings.

        Args:
            findings: list of tuples: (num, bucket, region, restriction_note)
            explanation: introductory paragraph
        """
        self.safe_page_break(60)
        self.section_title("Detailed Verdicts - False Positives (IP-Restricted)")
        if explanation:
            self.body_text(explanation)
            self.ln(1)
        for num, bucket, region, note in findings:
            self.safe_page_break(25)
            self.verdict_risk_badges("FALSE POSITIVE", "LOW")
            self.kv("Finding #", str(num))
            self.kv("Bucket", f"{bucket} ({region})")
            self.kv("Restriction", note)
            self.ln(2)
        self.ln(1)
        self.body_text(
            'Recommendation: Replace Principal:"*" with IAM principals for defense-in-depth.'
        )

    def remediation_section(self, items):
        """Render priority remediation list.

        Args:
            items: list of tuples: (priority, target, description)
                   priority is one of IMMEDIATE / URGENT / HIGH / MEDIUM / LOW
        """
        self.add_page()
        self.section_title("Priority Remediation Order")

        for priority, target, description in items:
            self.safe_page_break(25)
            r, g, b = PRIORITY_COLORS.get(priority, (0, 0, 0))
            self.badge(priority, r, g, b)
            self._set_text(0, 0, 0)
            self.set_font("Helvetica", "B", 9)
            vw = self.w - self.get_x() - self.r_margin
            self.cell(vw, 5.5, f"  {target}", new_x="LMARGIN", new_y="NEXT")
            self.set_x(self.l_margin + 6)
            self.set_font("Helvetica", "", 8)
            self._set_text(60, 60, 60)
            self.multi_cell(
                self.w - self.l_margin - self.r_margin - 6, 4.5, description,
                new_x="LMARGIN", new_y="NEXT",
            )
            self._set_text(0, 0, 0)
            self.ln(4)

    def save(self, path):
        """Write the PDF to disk."""
        self.output(path)
        return path
