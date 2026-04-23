"""
Chart generator for Prowler analysis reports.

Produces consistent matplotlib charts with a dark theme.
All charts are saved as PNGs and returned as file paths for PDF embedding.
"""

import os
import tempfile
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


# ── Theme ────────────────────────────────────────────────────────────────
BG = "#1a1a2e"
TEXT_COLOR = "white"
GRID_COLOR = "#333333"
SPINE_COLOR = "#333333"

VERDICT_COLORS = ["#dc3545", "#28a745", "#e67e22"]       # TP, FP, PT
RISK_COLORS = ["#dc3545", "#e67e22", "#d4a017", "#28a745"]  # CRIT, HIGH, MED, LOW
REGION_COLORS = ["#3498db", "#9b59b6", "#1abc9c", "#e74c3c", "#f39c12", "#2ecc71"]
EXPOSURE_COLORS = ["#dc3545", "#d4a017", "#3498db", "#9b59b6"]


class ChartGenerator:
    """Generate chart PNGs for Prowler reports.

    Usage:
        cg = ChartGenerator()
        paths = cg.generate_all(
            verdicts={"TRUE POSITIVE": 12, "FALSE POSITIVE": 5, "PARTIALLY TRUE": 2},
            risks={"CRITICAL": 2, "HIGH": 3, "MEDIUM": 7, "LOW": 6},
            exposure={"Truly Public": 12, "IP-Restricted": 5, "VPC-Only": 1},
            regions={"us-east-1": 16, "eu-west-1": 3},
        )
        # paths = {"verdict": "/tmp/.../verdict.png", "risk": ..., "exposure": ..., "region": ...}
        # Embed in PDF, then call cg.cleanup()
    """

    def __init__(self, out_dir=None):
        self.out_dir = out_dir or tempfile.mkdtemp(prefix="prowler_charts_")
        self.files = []

    # ── Public API ───────────────────────────────────────────────────────

    def generate_all(self, verdicts, risks, exposure=None, regions=None):
        """Generate all applicable charts. Returns dict of {name: filepath}."""
        paths = {}
        if verdicts:
            paths["verdict"] = self.donut(
                verdicts, "Verdict Distribution", VERDICT_COLORS, "verdict.png"
            )
        if risks:
            paths["risk"] = self.hbar(
                risks, "Risk Severity Breakdown", RISK_COLORS, "risk.png"
            )
        if exposure:
            paths["exposure"] = self.donut(
                exposure, "Policy Exposure Types", EXPOSURE_COLORS, "exposure.png"
            )
        if regions:
            paths["region"] = self.donut(
                regions, "Findings by Region", REGION_COLORS[: len(regions)], "region.png"
            )
        return paths

    def cleanup(self):
        """Remove all generated chart files and the temp directory."""
        for f in self.files:
            if os.path.exists(f):
                os.remove(f)
        if os.path.isdir(self.out_dir) and self.out_dir.startswith(tempfile.gettempdir()):
            try:
                os.rmdir(self.out_dir)
            except OSError:
                pass

    # ── Chart types ──────────────────────────────────────────────────────

    def donut(self, data, title, colors, filename):
        path = os.path.join(self.out_dir, filename)
        fig, ax = plt.subplots(figsize=(4, 3.2), facecolor=BG)
        ax.set_facecolor(BG)

        labels = [f"{k}\n({v})" for k, v in data.items()]
        wedges, texts, autotexts = ax.pie(
            data.values(),
            labels=None,
            autopct="%1.0f%%",
            startangle=90,
            colors=colors[: len(data)],
            wedgeprops=dict(width=0.45, edgecolor=BG, linewidth=2),
            textprops=dict(color=TEXT_COLOR, fontsize=8),
            pctdistance=0.75,
        )
        for t in autotexts:
            t.set_fontweight("bold")
            t.set_fontsize(9)

        ncol = min(len(data), 3)
        ax.legend(
            labels,
            loc="lower center",
            bbox_to_anchor=(0.5, -0.18),
            ncol=ncol,
            fontsize=7,
            frameon=False,
            labelcolor=TEXT_COLOR,
        )
        ax.set_title(title, color=TEXT_COLOR, fontsize=11, fontweight="bold", pad=10)
        fig.tight_layout()
        fig.savefig(path, dpi=150, bbox_inches="tight", facecolor=BG)
        plt.close(fig)
        self.files.append(path)
        return path

    def hbar(self, data, title, colors, filename):
        path = os.path.join(self.out_dir, filename)
        fig, ax = plt.subplots(figsize=(4, 3.2), facecolor=BG)
        ax.set_facecolor(BG)

        cats = list(data.keys())
        vals = list(data.values())
        bars = ax.barh(cats, vals, color=colors[: len(data)], edgecolor=BG, height=0.6)
        for bar, v in zip(bars, vals):
            ax.text(
                bar.get_width() + 0.3,
                bar.get_y() + bar.get_height() / 2,
                str(v),
                va="center",
                color=TEXT_COLOR,
                fontweight="bold",
                fontsize=10,
            )

        ax.set_xlim(0, max(vals) * 1.3 if vals else 1)
        ax.set_title(title, color=TEXT_COLOR, fontsize=11, fontweight="bold", pad=10)
        ax.tick_params(axis="y", colors=TEXT_COLOR, labelsize=8)
        ax.xaxis.set_visible(False)
        for spine in ("top", "right"):
            ax.spines[spine].set_visible(False)
        for spine in ("bottom", "left"):
            ax.spines[spine].set_color(SPINE_COLOR)

        fig.tight_layout()
        fig.savefig(path, dpi=150, bbox_inches="tight", facecolor=BG)
        plt.close(fig)
        self.files.append(path)
        return path
