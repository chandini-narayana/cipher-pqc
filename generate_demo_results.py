#!/usr/bin/env python3
"""Standalone CIPHER demo-results visualization generator.

PRESENTATION / EVALUATION TOOLING ONLY.

This script reads the already-verified evaluation artifacts under
``data/evaluation/research/`` and renders a self-contained, offline HTML
results page plus standalone SVG charts into ``demo_results/``.

It is deliberately inert with respect to the rest of the project:

* It imports nothing from CIPHER. It only reads JSON/CSV and ``README.md``.
* It never writes outside the chosen output directory.
* It does not touch the dashboard, runtime, QRS, ML, fusion, capture or
  enforcement code paths.
* It has no third-party dependencies -- charts are hand-rendered SVG from
  the Python standard library alone, so nothing is added to
  ``requirements.txt`` and the generated page needs no network access.

Every number on the page is read out of the source artifacts at generation
time. Nothing measured is hardcoded. When a required value is absent the page
shows "Result unavailable" instead of inventing one.

Usage:
    python generate_demo_results.py
    python generate_demo_results.py --out demo_results --open
"""

from __future__ import annotations

import argparse
import csv
import datetime as _dt
import html
import json
import math
import re
import sys
import webbrowser
from pathlib import Path
from typing import Any, Sequence

GENERATOR_VERSION = "1.0.0"

PROJECT_ROOT = Path(__file__).resolve().parent
RESEARCH_DIR = PROJECT_ROOT / "data" / "evaluation" / "research"
README_PATH = PROJECT_ROOT / "README.md"

UNAVAILABLE = "Result unavailable"

# Distinct from UNAVAILABLE: the source never carries this field, so nothing is
# actually missing. Kept separate so the page's "Result unavailable" count stays
# an honest signal of absent results.
NOT_APPLICABLE = "not applicable"

# The provenance class that must accompany every figure on this page.
EVIDENCE_CLASS = "CONTROLLED / SYNTHETIC / OFFLINE"


# ---------------------------------------------------------------------------
# Source loading
# ---------------------------------------------------------------------------


class Missing:
    """Sentinel for a value that could not be sourced.

    Distinct from ``None``, because ``None`` is itself a legitimate measured
    value in these artifacts (an unmeasurable p99, a null peak RSS).
    """

    __slots__ = ("reason",)

    def __init__(self, reason: str = "not present in source artifact") -> None:
        self.reason = reason

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "Missing({0!r})".format(self.reason)

    def __bool__(self) -> bool:
        return False


MISSING = Missing()


def _relpath(path: Path) -> str:
    try:
        return path.relative_to(PROJECT_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


class SourceSet:
    """The evaluation artifacts this page is built from, plus provenance."""

    JSON_SPECS = {
        "qrs": "latest_qrs_evaluation.json",
        "ml": "latest_ml_evaluation.json",
        "phase2d": "latest_phase2d_evaluation.json",
        "performance": "latest_performance.json",
    }

    CSV_SPECS = {
        "qrs_observations": "qrs_observations.csv",
        "ml_feature_distribution": "ml_feature_distribution.csv",
        "ml_observations": "ml_observations.csv",
        "performance_metrics": "performance_metrics.csv",
    }

    def __init__(self, research_dir: Path) -> None:
        self.research_dir = research_dir
        self.data: dict[str, Any] = {}
        self.provenance: list[dict[str, Any]] = []
        self._load()

    def _record(self, key: str, path: Path, status: str, detail: str = "") -> dict:
        entry = {
            "key": key,
            "name": path.name,
            "relpath": _relpath(path),
            "status": status,
            "detail": detail,
            "modified": UNAVAILABLE,
            "size": UNAVAILABLE,
            # CSV artifacts carry no embedded evaluation timestamp by design, so
            # their absence is "not applicable" rather than a missing result.
            "artifact_timestamp": NOT_APPLICABLE
            if path.suffix.lower() == ".csv"
            else UNAVAILABLE,
        }
        if path.exists():
            stat = path.stat()
            entry["size"] = "{0:,} B".format(stat.st_size)
            entry["modified"] = _dt.datetime.fromtimestamp(
                stat.st_mtime, _dt.timezone.utc
            ).strftime("%Y-%m-%d %H:%M:%S UTC")
        self.provenance.append(entry)
        return entry

    def _load(self) -> None:
        for key, name in self.JSON_SPECS.items():
            path = self.research_dir / name
            if not path.exists():
                self.data[key] = Missing("file not found: " + _relpath(path))
                self._record(key, path, "missing", "file not found")
                continue
            try:
                with path.open("r", encoding="utf-8") as handle:
                    payload = json.load(handle)
            except (OSError, json.JSONDecodeError) as exc:
                self.data[key] = Missing("{0}: {1}".format(type(exc).__name__, exc))
                self._record(key, path, "unreadable", "{0}: {1}".format(type(exc).__name__, exc))
                continue
            self.data[key] = payload
            entry = self._record(key, path, "loaded")
            if isinstance(payload, dict) and isinstance(payload.get("timestamp"), str):
                entry["artifact_timestamp"] = payload["timestamp"]

        for key, name in self.CSV_SPECS.items():
            path = self.research_dir / name
            if not path.exists():
                self.data[key] = Missing("file not found: " + _relpath(path))
                self._record(key, path, "missing", "file not found")
                continue
            try:
                with path.open("r", encoding="utf-8", newline="") as handle:
                    rows = list(csv.DictReader(handle))
            except OSError as exc:
                self.data[key] = Missing("{0}: {1}".format(type(exc).__name__, exc))
                self._record(key, path, "unreadable", str(exc))
                continue
            self.data[key] = rows
            self._record(key, path, "loaded", "{0} rows".format(len(rows)))

    def get(self, dotted: str) -> Any:
        """Resolve a dotted key path, e.g. ``qrs.qrs_conformance.score.f1``.

        Returns a ``Missing`` if any step is absent, so a renamed or removed
        key degrades to "Result unavailable" rather than raising.
        """
        parts = dotted.split(".")
        root = parts[0]
        node: Any = self.data.get(root, Missing("unknown source '" + root + "'"))
        if isinstance(node, Missing):
            return Missing("source artifact '{0}' unavailable".format(root))
        for part in parts[1:]:
            if isinstance(node, dict) and part in node:
                node = node[part]
            elif isinstance(node, list) and part.isdigit() and int(part) < len(node):
                node = node[int(part)]
            else:
                return Missing("key path '{0}' not found in source".format(dotted))
        return node


def read_pytest_baseline(readme: Path) -> dict[str, Any]:
    """Source the pytest baseline from README.md rather than hardcoding it.

    The suite total is not emitted into any evaluation JSON, so README.md is
    the single source of truth. If the sentence is absent or reworded, the
    card reports "Result unavailable" rather than a stale number.
    """
    result: dict[str, Any] = {
        "value": MISSING,
        "passed": MISSING,
        "failed": MISSING,
        "source": _relpath(readme),
        "line": MISSING,
    }
    if not readme.exists():
        result["value"] = Missing("README.md not found")
        return result
    try:
        text = readme.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        result["value"] = Missing("README.md unreadable: {0}".format(exc))
        return result

    pattern = re.compile(
        r"Current verified baseline:\s*\*\*\s*([\d,]+)\s+passed,\s*([\d,]+)\s+failed\s*\*\*",
        re.IGNORECASE,
    )
    for index, line in enumerate(text.splitlines(), start=1):
        match = pattern.search(line)
        if match:
            passed = int(match.group(1).replace(",", ""))
            failed = int(match.group(2).replace(",", ""))
            result.update(
                value="{0:,} passed".format(passed),
                passed=passed,
                failed=failed,
                line=index,
            )
            return result
    result["value"] = Missing("baseline sentence not found in README.md")
    return result


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------


def is_num(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and not (
        isinstance(value, float) and (math.isnan(value) or math.isinf(value))
    )


def fmt_pct(value: Any, places: int = 1) -> str:
    if not is_num(value):
        return UNAVAILABLE
    return "{0:.{1}f}%".format(value * 100.0, places)


def fmt_ms(value: Any) -> str:
    if not is_num(value):
        return UNAVAILABLE
    if value >= 100:
        return "{0:,.0f} ms".format(value)
    if value >= 1:
        return "{0:.2f} ms".format(value)
    if value >= 0.01:
        return "{0:.3f} ms".format(value)
    return "{0:.4f} ms".format(value)


def fmt_num(value: Any, places: int = 2) -> str:
    if not is_num(value):
        return UNAVAILABLE
    if float(value).is_integer() and abs(value) < 1e15:
        return "{0:,}".format(int(value))
    return "{0:,.{1}f}".format(value, places)


def fmt_count(value: Any) -> str:
    if not is_num(value):
        return UNAVAILABLE
    return "{0:,}".format(int(value))


def e(text: Any) -> str:
    """HTML-escape, rendering a Missing as the unavailable sentinel."""
    if isinstance(text, Missing):
        return UNAVAILABLE
    return html.escape(str(text), quote=True)


# ---------------------------------------------------------------------------
# SVG chart primitives
#
# Hand-rendered SVG, standard library only. Design tokens and mark specs
# follow the project's data-visualisation conventions: <=24px bars with a 4px
# rounded data-end squared to the baseline, 2px surface gaps between touching
# marks, 2px surface rings on overlapping dots, hairline solid gridlines,
# text in ink tokens (never the series colour), a legend whenever two or more
# series are present, and a selected dark mode rather than an inverted one.
# ---------------------------------------------------------------------------

FONT_STACK = 'system-ui, -apple-system, "Segoe UI", Roboto, sans-serif'

# Categorical slots, light / dark. Validated as a 5-slot adjacent set in both
# modes (worst adjacent CVD dE 9.1 light / 8.4 dark; normal-vision 19.6 / 19.3).
SERIES_LIGHT = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4"]
SERIES_DARK = ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181"]

TOKENS_LIGHT = {
    "surface": "#fcfcfb",
    "ink": "#0b0b0b",
    "ink2": "#52514e",
    "muted": "#898781",
    "grid": "#e1e0d9",
    "axis": "#c3c2b7",
}
TOKENS_DARK = {
    "surface": "#1a1a19",
    "ink": "#ffffff",
    "ink2": "#c3c2b7",
    "muted": "#898781",
    "grid": "#2c2c2a",
    "axis": "#383835",
}


def _token_block(n_series: int) -> str:
    """Per-SVG scoped token definitions.

    Emitted inside each ``<svg>`` so a standalone ``.svg`` file themes itself
    from the OS setting, while the same markup inlined in the results page
    also obeys that page's explicit ``data-theme`` toggle.
    """

    def decls(tokens: dict, series: list[str]) -> str:
        parts = ["--{0}:{1}".format(k, v) for k, v in tokens.items()]
        parts += ["--s{0}:{1}".format(i + 1, series[i]) for i in range(n_series)]
        return ";".join(parts) + ";"

    light = decls(TOKENS_LIGHT, SERIES_LIGHT)
    dark = decls(TOKENS_DARK, SERIES_DARK)
    return (
        ".cvz{{{light}}}"
        "@media (prefers-color-scheme: dark){{:root:not([data-theme=\"light\"]) .cvz{{{dark}}}}}"
        ":root[data-theme=\"dark\"] .cvz{{{dark}}}"
        ".cvz text{{font-family:{font};fill:var(--ink2)}}"
        ".cvz .cvz-t{{fill:var(--ink);font-weight:600}}"
        ".cvz .cvz-m{{fill:var(--muted)}}"
        ".cvz .cvz-v{{fill:var(--ink2);font-variant-numeric:tabular-nums}}"
        ".cvz .cvz-grid{{stroke:var(--grid);stroke-width:1}}"
        ".cvz .cvz-axis{{stroke:var(--axis);stroke-width:1}}"
        ".cvz .cvz-bg{{fill:var(--surface)}}"
    ).format(light=light, dark=dark, font=FONT_STACK)


def _svg(width: int, height: int, title: str, desc: str, body: str, n_series: int) -> str:
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" class="cvz" role="img" '
        'viewBox="0 0 {w} {h}" width="{w}" height="{h}" '
        'aria-labelledby="ttl desc" font-size="11">'
        "<title id=\"ttl\">{title}</title><desc id=\"desc\">{desc}</desc>"
        "<style>{style}</style>"
        '<rect class="cvz-bg" x="0" y="0" width="{w}" height="{h}"/>'
        "{body}</svg>"
    ).format(
        w=width,
        h=height,
        title=html.escape(title),
        desc=html.escape(desc),
        style=_token_block(n_series),
        body=body,
    )


def _rounded_top_bar(x: float, y: float, w: float, h: float, r: float = 4.0) -> str:
    """A column with a rounded data-end and square corners at the baseline."""
    if h <= 0:
        return ""
    rr = min(r, w / 2.0, h)
    return (
        '<path d="M{x:.2f},{b:.2f} L{x:.2f},{yr:.2f} '
        "Q{x:.2f},{y:.2f} {xr:.2f},{y:.2f} "
        "L{xe:.2f},{y:.2f} Q{x2:.2f},{y:.2f} {x2:.2f},{yr:.2f} "
        'L{x2:.2f},{b:.2f} Z"'
    ).format(x=x, b=y + h, yr=y + rr, y=y, xr=x + rr, xe=x + w - rr, x2=x + w)


def _rounded_right_bar(x: float, y: float, w: float, h: float, r: float = 4.0) -> str:
    """A horizontal bar with a rounded data-end, square at the baseline."""
    if w <= 0:
        return ""
    rr = min(r, h / 2.0, w)
    return (
        '<path d="M{x:.2f},{y:.2f} L{xr:.2f},{y:.2f} '
        "Q{xe:.2f},{y:.2f} {xe:.2f},{yr:.2f} "
        "L{xe:.2f},{yb:.2f} Q{xe:.2f},{y2:.2f} {xr:.2f},{y2:.2f} "
        'L{x:.2f},{y2:.2f} Z"'
    ).format(
        x=x, y=y, xr=x + w - rr, xe=x + w, yr=y + rr, yb=y + h - rr, y2=y + h
    )


def _legend(x: float, y: float, labels: Sequence[str], slots: Sequence[int]) -> str:
    """A legend row. Always present for two or more series."""
    out = []
    cursor = x
    for label, slot in zip(labels, slots):
        out.append(
            '<rect x="{x:.1f}" y="{y:.1f}" width="10" height="10" rx="2" '
            'fill="var(--s{s})"/>'.format(x=cursor, y=y - 8, s=slot)
        )
        out.append(
            '<text x="{x:.1f}" y="{y:.1f}">{t}</text>'.format(
                x=cursor + 15, y=y, t=html.escape(label)
            )
        )
        cursor += 15 + 7.1 * len(label) + 22
    return "".join(out)


def grouped_columns(
    title: str,
    desc: str,
    groups: Sequence[str],
    series: Sequence[dict],
    y_max: float = 1.0,
    value_fmt=fmt_pct,
    width: int = 900,
    height: int = 430,
) -> str:
    """Grouped column chart on a single shared 0..y_max axis.

    ``series`` is a list of ``{"label": str, "slot": int, "values": [...]}``.
    A value that is not a number is skipped and reported in the chart's own
    "no value in source" footnote rather than drawn as zero.
    """
    ml, mr, mt, mb = 58, 20, 66, 96
    plot_w = width - ml - mr
    plot_h = height - mt - mb
    n_groups = max(1, len(groups))
    n_series = max(1, len(series))

    band = plot_w / n_groups
    gap = 2.0  # surface gap between touching bars
    bar_w = min(24.0, (band * 0.62 - gap * (n_series - 1)) / n_series)
    cluster_w = bar_w * n_series + gap * (n_series - 1)

    parts: list[str] = []
    parts.append(
        '<text class="cvz-t" x="{x}" y="22" font-size="13">{t}</text>'.format(
            x=ml, t=html.escape(title)
        )
    )

    # Gridlines and y ticks, rounded to clean numbers.
    ticks = 5
    for i in range(ticks):
        frac = i / (ticks - 1)
        y = mt + plot_h - frac * plot_h
        parts.append(
            '<line class="cvz-grid" x1="{a}" y1="{y:.1f}" x2="{b}" y2="{y:.1f}"/>'.format(
                a=ml, y=y, b=ml + plot_w
            )
        )
        parts.append(
            '<text class="cvz-m cvz-v" x="{x}" y="{y:.1f}" text-anchor="end">'
            "{v:.0f}%</text>".format(x=ml - 8, y=y + 3.5, v=frac * y_max * 100)
        )
    parts.append(
        '<line class="cvz-axis" x1="{a}" y1="{y}" x2="{b}" y2="{y}"/>'.format(
            a=ml, y=mt + plot_h, b=ml + plot_w
        )
    )

    skipped: list[str] = []
    for gi, group in enumerate(groups):
        cx = ml + band * gi + band / 2.0
        x0 = cx - cluster_w / 2.0

        # Draw the bars first, collecting where each cap label wants to sit.
        pending: list[tuple[float, float, str]] = []
        for si, spec in enumerate(series):
            raw = spec["values"][gi] if gi < len(spec["values"]) else MISSING
            bx = x0 + si * (bar_w + gap)
            if not is_num(raw):
                skipped.append("{0} / {1}".format(group, spec["label"]))
                parts.append(
                    '<text class="cvz-m" x="{x:.1f}" y="{y:.1f}" '
                    'text-anchor="middle" font-size="9">n/a</text>'.format(
                        x=bx + bar_w / 2.0, y=mt + plot_h - 6
                    )
                )
                continue
            frac = max(0.0, min(1.0, float(raw) / y_max)) if y_max else 0.0
            bh = frac * plot_h
            by = mt + plot_h - bh
            parts.append(
                _rounded_top_bar(bx, by, bar_w, bh)
                + ' fill="var(--s{s})"/>'.format(s=spec["slot"])
            )
            pending.append((bx + bar_w / 2.0, by - 5, value_fmt(raw)))

        # Cap labels are wider than the bar pitch, so two bars of near-equal
        # height would collide. Lift the earlier label clear instead of letting
        # the two overprint each other.
        for idx in range(len(pending) - 1, 0, -1):
            x_cur, y_cur, _ = pending[idx]
            x_prev, y_prev, text_prev = pending[idx - 1]
            if abs(y_cur - y_prev) < 13:
                pending[idx - 1] = (x_prev, min(y_prev, y_cur) - 13, text_prev)
        for lx, ly, text in pending:
            parts.append(
                '<text class="cvz-v" x="{x:.1f}" y="{y:.1f}" '
                'text-anchor="middle" font-size="9.5">{v}</text>'.format(
                    x=lx, y=max(ly, 42.0), v=html.escape(text)
                )
            )

        # Group label, wrapped onto at most two lines so nothing is clipped.
        words = group.split()
        lines: list[str] = []
        current = ""
        limit = max(10, int(band / 6.2))
        for word in words:
            trial = (current + " " + word).strip()
            if len(trial) > limit and current:
                lines.append(current)
                current = word
            else:
                current = trial
        if current:
            lines.append(current)
        for li, line in enumerate(lines[:3]):
            parts.append(
                '<text class="cvz-m" x="{x:.1f}" y="{y:.1f}" '
                'text-anchor="middle">{t}</text>'.format(
                    x=cx, y=mt + plot_h + 18 + li * 12, t=html.escape(line)
                )
            )

    if len(series) >= 2:
        parts.append(
            _legend(
                ml,
                height - 14,
                [s["label"] for s in series],
                [s["slot"] for s in series],
            )
        )
    if skipped:
        parts.append(
            '<text class="cvz-m" x="{x}" y="38" font-size="9.5">'
            "no value in source: {t}</text>".format(
                x=ml, t=html.escape(", ".join(skipped[:4]))
            )
        )
    return _svg(width, height, title, desc, "".join(parts), len(SERIES_LIGHT))


def log_dot_plot(
    title: str,
    desc: str,
    rows: Sequence[dict],
    series_labels: Sequence[str],
    width: int = 900,
    height: int = 400,
) -> str:
    """Dot plot on a log10 position axis.

    A dot plot, not bars: these latencies span several orders of magnitude,
    and bar *length* on a log axis would not encode magnitude honestly. Dots
    encode position, which a log axis supports, and every value is also
    direct-labelled so precision never depends on reading the axis.

    ``rows`` is a list of ``{"label": str, "values": [v1, v2]}`` in ms.
    """
    ml, mr, mt, mb = 230, 86, 54, 54
    plot_w = width - ml - mr
    plot_h = height - mt - mb

    values = [v for row in rows for v in row["values"] if is_num(v) and v > 0]
    if values:
        lo_exp = math.floor(math.log10(min(values)))
        hi_exp = math.ceil(math.log10(max(values)))
        if hi_exp <= lo_exp:
            hi_exp = lo_exp + 1
    else:
        lo_exp, hi_exp = -4, 1

    span = float(hi_exp - lo_exp)

    def xpos(value: float) -> float:
        return ml + (math.log10(value) - lo_exp) / span * plot_w

    parts: list[str] = []
    parts.append(
        '<text class="cvz-t" x="16" y="22" font-size="13">{t}</text>'.format(
            t=html.escape(title)
        )
    )
    parts.append(
        '<text class="cvz-m" x="16" y="38" font-size="9.5">'
        "horizontal axis is log10 milliseconds &#8212; every value is also "
        "labelled, so spacing is never load-bearing</text>"
    )

    for exp in range(lo_exp, hi_exp + 1):
        x = xpos(10.0 ** exp)
        parts.append(
            '<line class="cvz-grid" x1="{x:.1f}" y1="{a}" x2="{x:.1f}" y2="{b}"/>'.format(
                x=x, a=mt, b=mt + plot_h
            )
        )
        label = "{0:g}".format(10.0 ** exp)
        parts.append(
            '<text class="cvz-m cvz-v" x="{x:.1f}" y="{y}" text-anchor="middle">'
            "{t}</text>".format(x=x, y=mt + plot_h + 18, t=label)
        )
    parts.append(
        '<text class="cvz-m" x="{x:.1f}" y="{y}" text-anchor="middle">'
        "milliseconds (log scale)</text>".format(
            x=ml + plot_w / 2.0, y=mt + plot_h + 36
        )
    )
    parts.append(
        '<line class="cvz-axis" x1="{a}" y1="{y}" x2="{b}" y2="{y}"/>'.format(
            a=ml, y=mt + plot_h, b=ml + plot_w
        )
    )

    n_rows = max(1, len(rows))
    row_h = plot_h / n_rows
    skipped: list[str] = []
    for ri, row in enumerate(rows):
        cy = mt + row_h * ri + row_h / 2.0
        parts.append(
            '<text class="cvz-m" x="{x}" y="{y:.1f}" text-anchor="end">{t}</text>'.format(
                x=ml - 14, y=cy + 3.5, t=html.escape(row["label"])
            )
        )
        pts = [v for v in row["values"] if is_num(v) and v > 0]
        if not pts:
            skipped.append(row["label"])
            parts.append(
                '<text class="cvz-m" x="{x}" y="{y:.1f}" font-size="9.5">'
                "{u}</text>".format(x=ml + 6, y=cy + 3.5, u=UNAVAILABLE)
            )
            continue
        if len(pts) >= 2:
            parts.append(
                '<line x1="{a:.1f}" y1="{y:.1f}" x2="{b:.1f}" y2="{y:.1f}" '
                'stroke="var(--axis)" stroke-width="2" stroke-linecap="round"/>'.format(
                    a=xpos(min(pts)), y=cy, b=xpos(max(pts))
                )
            )
        for si, value in enumerate(row["values"]):
            if not is_num(value) or value <= 0:
                continue
            x = xpos(value)
            # 2px surface ring keeps overlapping dots legible.
            parts.append(
                '<circle cx="{x:.1f}" cy="{y:.1f}" r="6" fill="var(--s{s})" '
                'stroke="var(--surface)" stroke-width="2"/>'.format(
                    x=x, y=cy, s=si + 1
                )
            )
        # One direct label per row end, so the axis never has to be read precisely.
        tail = max(pts)
        parts.append(
            '<text class="cvz-v" x="{x:.1f}" y="{y:.1f}" font-size="9.5">'
            "{t}</text>".format(x=xpos(tail) + 11, y=cy + 3.5, t=html.escape(fmt_ms(tail)))
        )
        # The lower value gets a label on its own side, but only when there is
        # genuinely room between it and the axis -- a label is never clipped.
        head = min(pts)
        if len(pts) >= 2 and head < tail:
            label = fmt_ms(head)
            needed = 11 + 5.9 * len(label)
            if xpos(head) - needed >= ml + 2:
                parts.append(
                    '<text class="cvz-v" x="{x:.1f}" y="{y:.1f}" font-size="9.5" '
                    'text-anchor="end">{t}</text>'.format(
                        x=xpos(head) - 11, y=cy + 3.5, t=html.escape(label)
                    )
                )

    parts.append(_legend(16, height - 14, series_labels, [1, 2]))
    if skipped:
        parts.append(
            '<text class="cvz-m" x="{x}" y="{y}" font-size="9.5" '
            'text-anchor="end">{n} of {total} stages had no value in '
            "source</text>".format(
                x=width - 16, y=height - 14, n=len(skipped), total=len(rows)
            )
        )
    return _svg(width, height, title, desc, "".join(parts), len(SERIES_LIGHT))


def _nice_axis(lo: float, hi: float, ticks: int = 5, clamp_zero: bool = False):
    """Round an axis out to clean tick values.

    Returns ``(lo, hi, [tick values])``. ``clamp_zero`` holds the floor at zero
    for quantities that cannot be negative, so padding never invents a negative
    packet size.
    """
    if not (is_num(lo) and is_num(hi)):
        return 0.0, 1.0, [0.0, 1.0]
    if hi <= lo:
        hi = lo + max(abs(lo) * 0.1, 1.0)
    span = hi - lo
    raw_step = span / max(1, ticks - 1)
    magnitude = 10.0 ** math.floor(math.log10(raw_step)) if raw_step > 0 else 1.0
    for multiple in (1.0, 2.0, 2.5, 5.0, 10.0):
        step = magnitude * multiple
        if step >= raw_step:
            break
    lo_t = math.floor(lo / step) * step
    hi_t = math.ceil(hi / step) * step
    if clamp_zero and lo >= 0 and lo_t < 0:
        lo_t = 0.0
    values = []
    current = lo_t
    while current <= hi_t + step * 1e-9:
        values.append(0.0 if abs(current) < step * 1e-9 else current)
        current += step
    return lo_t, hi_t, values


def range_facets(
    title: str,
    desc: str,
    facets: Sequence[dict],
    cohorts: Sequence[str],
    width: int = 900,
    height: int = 520,
) -> str:
    """Small multiples of min-median-max ranges, one facet per feature.

    Two features on genuinely different scales get one facet each with its own
    axis -- never a second y-axis on a shared plot. Each cohort keeps its own
    categorical slot in every facet, so colour follows the entity.
    """
    ml, mr, mt = 196, 74, 66
    facet_gap = 62  # room for each facet's own tick row plus its successor's title
    legend_reserve = 42  # keeps the bottom facet's ticks clear of the legend row
    n_facets = max(1, len(facets))
    facet_h = (height - mt - legend_reserve - facet_gap * (n_facets - 1)) / n_facets
    plot_w = width - ml - mr

    parts: list[str] = []
    parts.append(
        '<text class="cvz-t" x="16" y="22" font-size="13">{t}</text>'.format(
            t=html.escape(title)
        )
    )
    parts.append(
        '<text class="cvz-m" x="16" y="38" font-size="9.5">'
        "bar spans observed min&#8211;max; the dot marks the median. "
        "Each feature has its own axis.</text>"
    )

    skipped: list[str] = []
    for fi, facet in enumerate(facets):
        top = mt + fi * (facet_h + facet_gap)
        stats = facet["stats"]
        vals = [
            v
            for cohort in cohorts
            for v in (
                stats.get(cohort, {}).get("min"),
                stats.get(cohort, {}).get("max"),
            )
            if is_num(v)
        ]
        raw_lo = min(vals) if vals else 0.0
        raw_hi = max(vals) if vals else 1.0
        lo, hi, tick_values = _nice_axis(
            raw_lo, raw_hi, ticks=5, clamp_zero=bool(facet.get("non_negative"))
        )

        def xpos(value: float, lo=lo, hi=hi) -> float:
            return ml + (value - lo) / (hi - lo) * plot_w

        parts.append(
            '<text class="cvz-t" x="16" y="{y:.1f}" font-size="11">{t}</text>'.format(
                y=top - 8, t=html.escape(facet["label"])
            )
        )
        for tick in tick_values:
            x = xpos(tick)
            parts.append(
                '<line class="cvz-grid" x1="{x:.1f}" y1="{a:.1f}" '
                'x2="{x:.1f}" y2="{b:.1f}"/>'.format(x=x, a=top, b=top + facet_h)
            )
            parts.append(
                '<text class="cvz-m cvz-v" x="{x:.1f}" y="{y:.1f}" '
                'text-anchor="middle" font-size="9">{t}</text>'.format(
                    x=x, y=top + facet_h + 16, t=html.escape(facet["fmt"](tick))
                )
            )
        parts.append(
            '<line class="cvz-axis" x1="{a:.1f}" y1="{y:.1f}" x2="{b:.1f}" '
            'y2="{y:.1f}"/>'.format(a=ml, y=top + facet_h, b=ml + plot_w)
        )

        n_cohorts = max(1, len(cohorts))
        row_h = facet_h / n_cohorts
        bar_h = min(14.0, row_h - 6.0)
        for ci, cohort in enumerate(cohorts):
            cy = top + row_h * ci + row_h / 2.0
            parts.append(
                '<text class="cvz-m" x="{x}" y="{y:.1f}" text-anchor="end" '
                'font-size="9.5">{t}</text>'.format(
                    x=ml - 12, y=cy + 3.5, t=html.escape(cohort)
                )
            )
            stat = stats.get(cohort) or {}
            vmin, vmed, vmax = stat.get("min"), stat.get("median"), stat.get("max")
            if not (is_num(vmin) and is_num(vmax)):
                skipped.append("{0} / {1}".format(facet["label"], cohort))
                parts.append(
                    '<text class="cvz-m" x="{x}" y="{y:.1f}" font-size="9">'
                    "{u}</text>".format(x=ml + 6, y=cy + 3.5, u=UNAVAILABLE)
                )
                continue
            x1, x2 = xpos(vmin), xpos(vmax)
            parts.append(
                _rounded_right_bar(x1, cy - bar_h / 2.0, max(3.0, x2 - x1), bar_h)
                + ' fill="var(--s{s})" fill-opacity="0.34"/>'.format(s=ci + 1)
            )
            if is_num(vmed):
                parts.append(
                    '<circle cx="{x:.1f}" cy="{y:.1f}" r="5" fill="var(--s{s})" '
                    'stroke="var(--surface)" stroke-width="2"/>'.format(
                        x=xpos(vmed), y=cy, s=ci + 1
                    )
                )
                parts.append(
                    '<text class="cvz-v" x="{x:.1f}" y="{y:.1f}" font-size="9">'
                    "{t}</text>".format(
                        x=min(x2, ml + plot_w) + 10,
                        y=cy + 3.5,
                        t=html.escape(facet["fmt"](vmed)),
                    )
                )

    parts.append(
        _legend(16, height - 10, list(cohorts), list(range(1, len(cohorts) + 1)))
    )
    if skipped:
        parts.append(
            '<text class="cvz-m" x="{x}" y="{y}" font-size="9" text-anchor="end">'
            "no value in source: {n} cohort/feature pairs</text>".format(
                x=width - 16, y=height - 10, n=len(skipped)
            )
        )
    return _svg(width, height, title, desc, "".join(parts), len(SERIES_LIGHT))


# ---------------------------------------------------------------------------
# Chart construction from the source artifacts
# ---------------------------------------------------------------------------

METRIC_KEYS = [
    ("accuracy", "Accuracy"),
    ("precision", "Precision"),
    ("recall_sensitivity", "Recall"),
    ("specificity", "Specificity"),
    ("f1", "F1"),
    ("balanced_accuracy", "Balanced accuracy"),
]


def _metrics_from(node: Any, keys: Sequence[tuple]) -> list[Any]:
    if not isinstance(node, dict):
        return [MISSING for _ in keys]
    return [node.get(key, MISSING) for key, _ in keys]


def build_chart_qrs(src: SourceSet) -> dict:
    """Chart 1 -- QRS controlled classification metrics, both operating points."""
    base = "qrs.controlled_security_classification.operating_points"
    flagged = src.get(base + ".flagged_for_remediation")
    isolation = src.get(base + ".high_risk_isolation_eligible")

    groups = [label for _, label in METRIC_KEYS]
    series = [
        {
            "label": "Flagged for remediation (category != LOW)",
            "slot": 1,
            "values": _metrics_from(flagged, METRIC_KEYS),
        },
        {
            "label": "High-risk isolation eligible (raw QRS >= 7)",
            "slot": 2,
            "values": _metrics_from(isolation, METRIC_KEYS),
        },
    ]
    title = "QRS controlled classification metrics, by frozen operating point"
    svg = grouped_columns(
        title,
        "Agreement between CIPHER's two frozen deterministic operating points and an "
        "a-priori external security rubric, on a controlled synthetic offline set.",
        groups,
        series,
    )
    rows = []
    for gi, (_, label) in enumerate(METRIC_KEYS):
        rows.append([label] + [fmt_pct(s["values"][gi]) for s in series])
    counts = []
    for node, name in ((flagged, "Flagged for remediation"), (isolation, "High-risk isolation eligible")):
        c = node.get("counts") if isinstance(node, dict) else None
        if isinstance(c, dict):
            counts.append(
                "{0}: TP {1}, TN {2}, FP {3}, FN {4} of {5}".format(
                    name,
                    fmt_count(c.get("true_positives")),
                    fmt_count(c.get("true_negatives")),
                    fmt_count(c.get("false_positives")),
                    fmt_count(c.get("false_negatives")),
                    fmt_count(c.get("total")),
                )
            )
    return {
        "id": "qrs-classification",
        "section": "Chart 1 — Deterministic QRS classification",
        "title": title,
        "svg": svg,
        "table_head": ["Metric", "Flagged for remediation", "High-risk isolation eligible"],
        "table_rows": rows,
        "notes": counts,
        "interpretation": src.get("qrs.controlled_security_classification.interpretation"),
        "positive_class": src.get("qrs.controlled_security_classification.positive_class"),
        "citations": src.get("qrs.controlled_security_classification.external_rubric_citations"),
    }


def build_chart_if_comparison(src: SourceSet) -> dict:
    """Chart 2 -- original Phase 2B IF against the Phase 2D pipeline-aligned IF."""
    baseline = src.get("phase2d.phase_2b_baseline")
    frozen = src.get("phase2d.frozen_test")

    keys = list(METRIC_KEYS) + [("roc_auc", "ROC AUC")]

    def with_auc(node: Any) -> list[Any]:
        values = _metrics_from(node, METRIC_KEYS)
        auc: Any = MISSING
        if isinstance(node, dict):
            raw = node.get("roc_auc", MISSING)
            if isinstance(raw, dict):
                auc = raw.get("auc", MISSING)
            elif is_num(raw):
                auc = raw
        return values + [auc]

    series = [
        {"label": "Phase 2B Isolation Forest (synthetically trained)", "slot": 1,
         "values": with_auc(baseline)},
        {"label": "Phase 2D Isolation Forest (pipeline-aligned candidate)", "slot": 2,
         "values": with_auc(frozen)},
    ]
    title = "Isolation Forest: original Phase 2B vs pipeline-aligned Phase 2D candidate"
    svg = grouped_columns(
        title,
        "Both evaluated on the same 24-observation frozen controlled test cohort. "
        "The Phase 2D artifact is an unpromoted candidate, not the deployed model.",
        [label for _, label in keys],
        series,
    )
    rows = []
    for gi, (_, label) in enumerate(keys):
        rows.append([label] + [fmt_pct(s["values"][gi]) for s in series])
    notes = []
    b_src = baseline.get("source") if isinstance(baseline, dict) else None
    if isinstance(b_src, str):
        notes.append("Phase 2B baseline source: " + b_src)
    cand = src.get("phase2d.candidate_artifact")
    prod = src.get("phase2d.production_artifact_untouched")
    if isinstance(cand, str):
        notes.append("Phase 2D candidate artifact: " + Path(cand).as_posix())
    if isinstance(prod, str):
        notes.append("Production artifact, left untouched: " + Path(prod).as_posix())
    allp = src.get("phase2d.acceptance.all_passed")
    if isinstance(allp, bool):
        notes.append(
            "Pre-frozen acceptance criteria: {0} (specificity and false-positive "
            "rate did not meet their thresholds).".format(
                "all passed" if allp else "NOT all passed"
            )
        )
    return {
        "id": "if-comparison",
        "section": "Chart 2 — Isolation Forest model comparison",
        "title": title,
        "svg": svg,
        "table_head": ["Metric", "Phase 2B IF", "Phase 2D IF candidate"],
        "table_rows": rows,
        "notes": notes,
        "acceptance": src.get("phase2d.acceptance.criteria"),
    }


def build_chart_latency(src: SourceSet) -> dict:
    """Chart 3 -- Windows per-packet latency comparison."""
    specs = [
        ("Enforcement decision (software only)", "performance.software_enforcement_decision_latency"),
        ("QRS-only assessment", "performance.qrs_only_assessment_latency"),
        ("Full pipeline, QRS-only", "performance.full_pipeline_latency.qrs_only"),
        ("QRS + Isolation Forest assessment", "performance.qrs_plus_isolation_forest_assessment_latency"),
        ("Full pipeline, with Isolation Forest", "performance.full_pipeline_latency.with_isolation_forest"),
    ]
    rows = []
    table_rows = []
    for label, path in specs:
        node = src.get(path)
        mean = node.get("mean_ms", MISSING) if isinstance(node, dict) else MISSING
        p95 = node.get("p95_ms", MISSING) if isinstance(node, dict) else MISSING
        median = node.get("median_ms", MISSING) if isinstance(node, dict) else MISSING
        n = node.get("n", MISSING) if isinstance(node, dict) else MISSING
        rows.append({"label": label, "values": [mean, p95]})
        table_rows.append(
            [label, fmt_ms(mean), fmt_ms(median), fmt_ms(p95), fmt_count(n)]
        )

    title = "Per-packet latency on this Windows host, controlled offline benchmark"
    svg = log_dot_plot(
        title,
        "Mean and p95 per-packet latency for each assessment stage, measured offline "
        "on one Windows development host. Not a production or Raspberry Pi figure.",
        rows,
        ["Mean", "p95"],
    )
    notes = []
    system = src.get("performance.system")
    if isinstance(system, dict):
        notes.append(
            "Host: {0} {1} / {2} / Python {3} / scikit-learn {4} / numpy {5}".format(
                system.get("system", "?"),
                system.get("release", "?"),
                system.get("machine", "?"),
                system.get("python_version", "?"),
                system.get("sklearn_version", "?"),
                system.get("numpy_version", "?"),
            )
        )
    mode = src.get("performance.benchmark_mode")
    if isinstance(mode, str):
        notes.append("Benchmark mode: " + mode)
    config = src.get("performance.configuration")
    if isinstance(config, dict):
        notes.append(
            "Configuration: {0} repetitions/packet, {1} warm-up calls/packet, clock {2}".format(
                config.get("latency_repetitions_per_packet", "?"),
                config.get("warmup_calls_per_packet", "?"),
                config.get("clock", "?"),
            )
        )
    scope = src.get("performance.software_enforcement_decision_latency.scope")
    if isinstance(scope, str):
        notes.append("Enforcement scope: " + scope)
    overhead = src.get("performance.incremental_ml_overhead.mean_ms")
    if is_num(overhead):
        notes.append(
            "Incremental Isolation Forest overhead, paired mean: " + fmt_ms(overhead)
        )
    return {
        "id": "latency",
        "section": "Chart 3 — Latency profile",
        "title": title,
        "svg": svg,
        "table_head": ["Stage", "Mean", "Median", "p95", "Samples"],
        "table_rows": table_rows,
        "notes": notes,
        "definition": src.get("performance.full_pipeline_latency.definition"),
    }


def build_chart_train_serve(src: SourceSet) -> dict:
    """Chart 4 -- train/serve feature-distribution comparison."""
    cohort_map = [
        ("training_normal", "Train: normal"),
        ("training_outlier", "Train: outlier"),
        ("pipeline_safe", "Serve: SAFE"),
        ("pipeline_risky", "Serve: RISKY"),
        ("pipeline_excluded", "Serve: EXCLUDED"),
    ]
    # Both features are physically non-negative, so the axis floor is held at
    # zero rather than padded into negative territory.
    features = [
        ("shannon_entropy", "Shannon entropy (bits)", lambda v: "{0:.2f}".format(v)),
        ("packet_size", "Packet size (bytes)", lambda v: "{0:,.0f}".format(v)),
    ]
    facets = []
    for key, label, formatter in features:
        node = src.get("ml.train_serve_feature_comparison.features." + key)
        stats: dict[str, Any] = {}
        for raw_name, display in cohort_map:
            value = node.get(raw_name) if isinstance(node, dict) else None
            stats[display] = value if isinstance(value, dict) else {}
        facets.append(
            {
                "label": label,
                "stats": stats,
                "fmt": formatter,
                "non_negative": True,
            }
        )

    cohorts = [display for _, display in cohort_map]
    title = "Train/serve feature-distribution comparison (Phase 2B training cohorts)"
    svg = range_facets(
        title,
        "Observed min/median/max of two model input features, comparing the cohorts the "
        "Phase 2B model was fitted on against the cohorts the real pipeline produces.",
        facets,
        cohorts,
    )

    table_head = ["Feature", "Cohort", "Count", "Min", "Median", "Max", "Mean", "Zero fraction"]
    table_rows = []
    for key, label, formatter in features:
        node = src.get("ml.train_serve_feature_comparison.features." + key)
        for raw_name, display in cohort_map:
            stat = node.get(raw_name) if isinstance(node, dict) else None
            if not isinstance(stat, dict):
                table_rows.append([label, display] + [UNAVAILABLE] * 6)
                continue
            table_rows.append(
                [
                    label,
                    display,
                    fmt_count(stat.get("count")),
                    fmt_num(stat.get("min"), 3),
                    fmt_num(stat.get("median"), 3),
                    fmt_num(stat.get("max"), 3),
                    fmt_num(stat.get("mean"), 3),
                    fmt_pct(stat.get("zero_fraction")),
                ]
            )

    # The source emits structural findings in two distinct shapes -- zero-value
    # fractions for the indicator-style features, and observed [min, max] ranges
    # for the continuous ones. Render each shape in its own table rather than
    # forcing them into one grid full of empty cells.
    findings = src.get("ml.train_serve_feature_comparison.structural_findings")
    zero_rows: list[list[Any]] = []
    range_rows: list[list[Any]] = []
    finding_cohorts = [
        ("training_normal", "Train normal"),
        ("training_outlier", "Train outlier"),
        ("pipeline_safe", "Serve SAFE"),
        ("pipeline_risky", "Serve RISKY"),
    ]
    if isinstance(findings, list):
        for item in findings:
            if not isinstance(item, dict):
                continue
            feature = item.get("feature", UNAVAILABLE)
            if any(k.endswith("_zero_fraction") for k in item):
                zero_rows.append(
                    [feature]
                    + [
                        fmt_pct(item.get(raw + "_zero_fraction"))
                        for raw, _ in finding_cohorts
                    ]
                )
            elif any(k.endswith("_range") for k in item):
                cells: list[Any] = [feature]
                for raw, _ in finding_cohorts:
                    span = item.get(raw + "_range")
                    if (
                        isinstance(span, (list, tuple))
                        and len(span) == 2
                        and is_num(span[0])
                        and is_num(span[1])
                    ):
                        cells.append(
                            "{0} – {1}".format(
                                fmt_num(span[0], 2), fmt_num(span[1], 2)
                            )
                        )
                    else:
                        cells.append(UNAVAILABLE)
                range_rows.append(cells)

    return {
        "id": "train-serve",
        "section": "Chart 4 — Train/serve feature skew",
        "title": title,
        "svg": svg,
        "table_head": table_head,
        "table_rows": table_rows,
        "notes": [],
        "interpretation": src.get("ml.train_serve_feature_comparison.interpretation"),
        "cohort_sizes": src.get("ml.train_serve_feature_comparison.cohort_sizes"),
        "zero_head": ["Feature"] + [label for _, label in finding_cohorts],
        "zero_rows": zero_rows,
        "range_head": ["Feature"] + [label for _, label in finding_cohorts],
        "range_rows": range_rows,
    }


# ---------------------------------------------------------------------------
# Metric cards
# ---------------------------------------------------------------------------


def build_cards(src: SourceSet, pytest_baseline: dict) -> list[dict]:
    cards: list[dict] = []

    exact = src.get("qrs.qrs_conformance.score.exact_matches")
    total = src.get("qrs.qrs_conformance.score.observation_count")
    if is_num(exact) and is_num(total):
        conformance = "{0}/{1}".format(fmt_count(exact), fmt_count(total))
        rate = src.get("qrs.qrs_conformance.score.exact_match_rate")
        sub = "exact match rate {0}".format(fmt_pct(rate)) if is_num(rate) else ""
    else:
        conformance, sub = UNAVAILABLE, ""
    cards.append(
        {
            "label": "QRS specification conformance",
            "value": conformance,
            "sub": sub,
            "detail": "Exact agreement between the implementation and the frozen "
            "published Quantum Risk Score formula. This is specification "
            "conformance, not detection accuracy.",
            "source": "latest_qrs_evaluation.json &rarr; qrs_conformance.score",
        }
    )

    mae = src.get("qrs.qrs_conformance.score.mean_absolute_error")
    max_err = src.get("qrs.qrs_conformance.score.max_absolute_error")
    cards.append(
        {
            "label": "QRS mean absolute error",
            "value": fmt_num(mae, 3) if is_num(mae) else UNAVAILABLE,
            "sub": "max absolute error {0}".format(fmt_num(max_err))
            if is_num(max_err)
            else "",
            "detail": "Deviation of computed scores from the reference formula across "
            "the controlled observation set. Zero means the implementation "
            "reproduces the specification exactly.",
            "source": "latest_qrs_evaluation.json &rarr; qrs_conformance.score",
        }
    )

    failed = pytest_baseline.get("failed")
    cards.append(
        {
            "label": "Current pytest baseline",
            "value": pytest_baseline.get("value"),
            "sub": "{0} failed".format(fmt_count(failed)) if is_num(failed) else "",
            "detail": "Full-suite result recorded in the project README. Sourced by "
            "parsing the README at generation time, not hardcoded here.",
            "source": "{0}{1}".format(
                pytest_baseline.get("source"),
                ":{0}".format(pytest_baseline["line"])
                if is_num(pytest_baseline.get("line"))
                else "",
            ),
        }
    )

    start_mean = src.get("performance.startup.mean_seconds")
    start_target = src.get("performance.startup.target_seconds")
    start_n = src.get("performance.startup.n")
    cards.append(
        {
            "label": "Startup time",
            "value": "{0:.2f} s".format(start_mean) if is_num(start_mean) else UNAVAILABLE,
            "sub": "mean of {0} runs, target {1}".format(
                fmt_count(start_n),
                "{0:.0f} s".format(start_target) if is_num(start_target) else "n/a",
            )
            if is_num(start_n)
            else "",
            "detail": src.get("performance.startup.boundary"),
            "source": "latest_performance.json &rarr; startup",
        }
    )

    rep_median = src.get("performance.report_generation_latency.median_ms")
    rep_p95 = src.get("performance.report_generation_latency.p95_ms")
    rep_n = src.get("performance.report_generation_latency.n")
    cards.append(
        {
            "label": "Report generation latency",
            "value": fmt_ms(rep_median),
            "sub": "median; p95 {0} over {1} runs".format(fmt_ms(rep_p95), fmt_count(rep_n))
            if is_num(rep_p95) and is_num(rep_n)
            else "",
            "detail": src.get("performance.report_generation_latency.scope"),
            "source": "latest_performance.json &rarr; report_generation_latency",
        }
    )

    return cards


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------

PAGE_CSS = """
*,*::before,*::after{box-sizing:border-box}
:root{
  color-scheme:light;
  --plane:#f9f9f7; --surface:#fcfcfb; --ink:#0b0b0b; --ink2:#52514e;
  --muted:#898781; --grid:#e1e0d9; --axis:#c3c2b7;
  --border:rgba(11,11,11,0.10);
  --warn:#fab219; --crit:#d03b3b; --good:#0ca30c; --serious:#ec835a;
  --accent:#2a78d6;
  --band:#fff6e0; --band-ink:#5c4304; --band-edge:rgba(250,178,25,0.55);
}
@media (prefers-color-scheme:dark){
  :root:not([data-theme="light"]){
    color-scheme:dark;
    --plane:#0d0d0d; --surface:#1a1a19; --ink:#ffffff; --ink2:#c3c2b7;
    --muted:#898781; --grid:#2c2c2a; --axis:#383835;
    --border:rgba(255,255,255,0.10);
    --accent:#3987e5;
    --band:#2a2206; --band-ink:#f5d78a; --band-edge:rgba(250,178,25,0.45);
  }
}
:root[data-theme="dark"]{
  color-scheme:dark;
  --plane:#0d0d0d; --surface:#1a1a19; --ink:#ffffff; --ink2:#c3c2b7;
  --muted:#898781; --grid:#2c2c2a; --axis:#383835;
  --border:rgba(255,255,255,0.10);
  --accent:#3987e5;
  --band:#2a2206; --band-ink:#f5d78a; --band-edge:rgba(250,178,25,0.45);
}
html{-webkit-text-size-adjust:100%}
body{
  margin:0; background:var(--plane); color:var(--ink);
  font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  font-size:15px; line-height:1.55;
}
.wrap{max-width:1000px;margin:0 auto;padding:32px 16px 72px}
header.masthead{display:flex;flex-wrap:wrap;gap:16px;align-items:flex-start;justify-content:space-between}
h1{font-size:1.5rem;line-height:1.25;margin:0 0 6px}
h2{font-size:1.1rem;margin:0 0 4px}
h3{font-size:0.95rem;margin:0 0 4px}
p{margin:0 0 10px}
.sub{color:var(--ink2);margin:0}
.evidence{
  display:inline-flex;align-items:center;gap:8px;margin:18px 0 0;
  padding:10px 14px;border-radius:8px;
  background:var(--band);color:var(--band-ink);
  border:1px solid var(--band-edge);
  font-weight:650;letter-spacing:0.04em;font-size:0.82rem;
}
.evidence svg{flex:none}
.callout{
  margin:14px 0 0;padding:12px 14px;border-radius:8px;
  background:var(--surface);border:1px solid var(--border);
  border-left:3px solid var(--warn);color:var(--ink2);font-size:0.88rem;
}
.callout strong{color:var(--ink)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(172px,1fr));gap:12px;margin:18px 0 0}
.card{
  background:var(--surface);border:1px solid var(--border);border-radius:10px;
  padding:14px 15px;display:flex;flex-direction:column;gap:3px;
}
.card .label{font-size:0.76rem;color:var(--muted);text-transform:uppercase;letter-spacing:0.06em}
.card .value{font-size:1.65rem;font-weight:620;line-height:1.1;color:var(--ink)}
.card .value.na{font-size:0.95rem;font-weight:500;color:var(--muted)}
.card .vsub{font-size:0.8rem;color:var(--ink2);font-variant-numeric:tabular-nums}
.card .detail{font-size:0.78rem;color:var(--muted);margin-top:6px}
.card .src{font-size:0.7rem;color:var(--muted);margin-top:6px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-word}
section.block{
  margin:22px 0 0;background:var(--surface);border:1px solid var(--border);
  border-radius:12px;padding:18px 18px 20px;
}
.figwrap{margin:14px -4px 0;overflow-x:auto}
.figwrap svg{display:block;max-width:100%;height:auto;min-width:640px}
figure{margin:0}
figcaption{font-size:0.84rem;color:var(--ink2);margin:10px 2px 0}
.tag{
  display:inline-block;font-size:0.68rem;letter-spacing:0.05em;font-weight:650;
  padding:2px 7px;border-radius:999px;border:1px solid var(--band-edge);
  background:var(--band);color:var(--band-ink);vertical-align:2px;margin-left:8px;
}
details{margin:12px 0 0;border-top:1px solid var(--border);padding-top:10px}
summary{cursor:pointer;font-size:0.85rem;color:var(--accent);font-weight:560}
summary:hover{text-decoration:underline}
.tscroll{overflow-x:auto;margin-top:10px}
table{border-collapse:collapse;width:100%;font-size:0.82rem}
th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--grid);white-space:nowrap}
th{color:var(--muted);font-weight:600;font-size:0.74rem;text-transform:uppercase;letter-spacing:0.04em}
td{font-variant-numeric:tabular-nums;color:var(--ink2)}
td:first-child,th:first-child{white-space:normal}
.na{color:var(--muted);font-style:italic;font-variant-numeric:normal}
ul.notes{margin:10px 0 0;padding-left:18px;font-size:0.82rem;color:var(--ink2)}
ul.notes li{margin:3px 0}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:0.85em}
.status{display:inline-flex;align-items:center;gap:5px;font-weight:600;font-size:0.8rem}
.status.pass{color:var(--good)}
.status.fail{color:var(--crit)}
.themebtn{
  background:var(--surface);color:var(--ink2);border:1px solid var(--border);
  border-radius:8px;padding:7px 12px;font:inherit;font-size:0.8rem;cursor:pointer;flex:none;
}
.themebtn:hover{color:var(--ink)}
footer{margin:28px 0 0;color:var(--muted);font-size:0.78rem}
@media (max-width:560px){
  .wrap{padding:22px 16px 56px}
  h1{font-size:1.28rem}
  .card .value{font-size:1.4rem}
}
"""

THEME_JS = """
(function(){
  var r=document.documentElement,b=document.getElementById('themebtn');
  function cur(){
    var s=r.getAttribute('data-theme');
    if(s)return s;
    return window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light';
  }
  function paint(){b.textContent=cur()==='dark'?'Light mode':'Dark mode';}
  try{var k=localStorage.getItem('cipher-demo-theme');if(k)r.setAttribute('data-theme',k);}catch(e){}
  paint();
  b.addEventListener('click',function(){
    var n=cur()==='dark'?'light':'dark';
    r.setAttribute('data-theme',n);
    try{localStorage.setItem('cipher-demo-theme',n);}catch(e){}
    paint();
  });
})();
"""

WARN_ICON = (
    '<svg width="15" height="15" viewBox="0 0 16 16" aria-hidden="true" fill="none" '
    'stroke="currentColor" stroke-width="1.6" stroke-linecap="round">'
    '<path d="M8 2.6 1.8 13.4h12.4z"/><path d="M8 6.4v3.2"/><path d="M8 11.6h.01"/></svg>'
)


def _cell(value: Any) -> str:
    text = e(value)
    cls = ' class="na"' if text == UNAVAILABLE else ""
    return "<td{0}>{1}</td>".format(cls, text)


def render_table(head: Sequence[str], rows: Sequence[Sequence[Any]]) -> str:
    if not rows:
        return '<p class="na">{0}</p>'.format(UNAVAILABLE)
    thead = "".join("<th>{0}</th>".format(e(h)) for h in head)
    body = "".join(
        "<tr>" + "".join(_cell(c) for c in row) + "</tr>" for row in rows
    )
    return (
        '<div class="tscroll"><table><thead><tr>{0}</tr></thead>'
        "<tbody>{1}</tbody></table></div>".format(thead, body)
    )


def render_notes(notes: Sequence[Any]) -> str:
    items = [n for n in notes if isinstance(n, str) and n.strip()]
    if not items:
        return ""
    return '<ul class="notes">{0}</ul>'.format(
        "".join("<li>{0}</li>".format(e(n)) for n in items)
    )


def render_card(card: dict) -> str:
    value = card["value"]
    text = e(value)
    na = " na" if text == UNAVAILABLE else ""
    sub = card.get("sub")
    sub_html = (
        '<div class="vsub">{0}</div>'.format(e(sub))
        if isinstance(sub, str) and sub.strip()
        else ""
    )
    detail = card.get("detail")
    detail_html = (
        '<div class="detail">{0}</div>'.format(e(detail))
        if isinstance(detail, str) and detail.strip()
        else ""
    )
    return (
        '<div class="card"><div class="label">{label}</div>'
        '<div class="value{na}">{value}</div>{sub}{detail}'
        '<div class="src">{src}</div></div>'
    ).format(
        label=e(card["label"]),
        na=na,
        value=text,
        sub=sub_html,
        detail=detail_html,
        src=card.get("source", ""),
    )


def render_chart_block(chart: dict, caption: str, extra: str = "") -> str:
    tables = render_table(chart["table_head"], chart["table_rows"])
    notes = render_notes(chart.get("notes", []))
    interp = chart.get("interpretation")
    interp_html = (
        '<p class="sub" style="font-size:0.86rem">{0}</p>'.format(e(interp))
        if isinstance(interp, str)
        else ""
    )
    return (
        '<section class="block" id="{cid}">'
        "<h2>{title}<span class=\"tag\">{cls}</span></h2>"
        "{interp}"
        '<figure><div class="figwrap">{svg}</div>'
        "<figcaption>{caption}</figcaption></figure>"
        "{notes}{extra}"
        "<details><summary>Show the underlying values as a table</summary>{tables}</details>"
        "</section>"
    ).format(
        cid=e(chart["id"]),
        title=e(chart.get("section") or chart["title"]),
        cls=EVIDENCE_CLASS,
        interp=interp_html,
        svg=chart["svg"],
        caption=caption,
        notes=notes,
        extra=extra,
        tables=tables,
    )


def render_page(src: SourceSet, charts: dict, cards: list[dict]) -> str:
    generated = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    prov_rows = [
        [
            p["relpath"],
            p["status"],
            p["artifact_timestamp"],
            p["modified"],
            p["size"],
            p["detail"] or "—",
        ]
        for p in src.provenance
    ]
    missing = [p for p in src.provenance if p["status"] != "loaded"]

    # Acceptance criteria table for the Phase 2D candidate.
    acceptance = charts["if_comparison"].get("acceptance")
    acc_rows = []
    if isinstance(acceptance, dict):
        for name, node in acceptance.items():
            if not isinstance(node, dict):
                continue
            passed = node.get("passed")
            if passed is True:
                status = '<span class="status pass">met</span>'
            elif passed is False:
                status = '<span class="status fail">not met</span>'
            else:
                status = '<span class="na">{0}</span>'.format(UNAVAILABLE)
            measured = node.get("measured")
            acc_rows.append(
                [
                    name.replace("_", " "),
                    fmt_pct(measured) if is_num(measured) else UNAVAILABLE,
                    node.get("criterion", UNAVAILABLE),
                    status,
                ]
            )
    acc_html = ""
    if acc_rows:
        thead = "".join(
            "<th>{0}</th>".format(h)
            for h in ("Criterion", "Measured", "Threshold", "Outcome")
        )
        body = "".join(
            "<tr>{0}{1}{2}<td>{3}</td></tr>".format(
                _cell(r[0]), _cell(r[1]), _cell(r[2]), r[3]
            )
            for r in acc_rows
        )
        acc_html = (
            "<details open><summary>Pre-frozen Phase 2D acceptance criteria</summary>"
            '<div class="tscroll"><table><thead><tr>{0}</tr></thead><tbody>{1}'
            "</tbody></table></div></details>".format(thead, body)
        )

    ts_chart = charts["train_serve"]
    finding_html = ""
    if ts_chart.get("zero_rows"):
        finding_html += (
            "<details><summary>Structural finding: zero-value fraction per cohort "
            "(indicator features)</summary>{0}</details>".format(
                render_table(ts_chart["zero_head"], ts_chart["zero_rows"])
            )
        )
    if ts_chart.get("range_rows"):
        finding_html += (
            "<details><summary>Structural finding: observed min&#8211;max range per "
            "cohort (continuous features)</summary>{0}</details>".format(
                render_table(ts_chart["range_head"], ts_chart["range_rows"])
            )
        )

    cohort_sizes = ts_chart.get("cohort_sizes")
    cohort_note = ""
    if isinstance(cohort_sizes, dict):
        cohort_note = render_notes(
            [
                "Cohort sizes: "
                + ", ".join(
                    "{0} = {1}".format(k.replace("_", " "), fmt_count(v))
                    for k, v in cohort_sizes.items()
                )
            ]
        )

    qrs_chart = charts["qrs"]
    citations = qrs_chart.get("citations")
    cite_html = ""
    if isinstance(citations, list) and citations:
        cite_html = render_notes(
            ["External rubric citation: " + str(c) for c in citations]
        )
    positive = qrs_chart.get("positive_class")
    positive_html = (
        '<div class="callout"><strong>Positive class.</strong> {0}</div>'.format(
            e(positive)
        )
        if isinstance(positive, str)
        else ""
    )

    latency_def = charts["latency"].get("definition")
    latency_def_html = (
        '<div class="callout"><strong>Measured stages.</strong> {0}</div>'.format(
            e(latency_def)
        )
        if isinstance(latency_def, str)
        else ""
    )

    missing_html = ""
    if missing:
        missing_html = (
            '<div class="callout"><strong>{0} source artifact(s) could not be read.</strong> '
            "Every figure that depended on them reads &#8220;{1}&#8221; below; no value was "
            "substituted or estimated. Affected: {2}.</div>"
        ).format(
            len(missing),
            UNAVAILABLE,
            e(", ".join(p["relpath"] for p in missing)),
        )

    blocks = [
        render_chart_block(
            qrs_chart,
            "Agreement between CIPHER&#8217;s two frozen deterministic operating points and an "
            "a-priori external security rubric, measured on a controlled set of synthetic, "
            "offline observations. Labels were fixed from published standards before "
            "execution and never derived from any CIPHER output. This is rubric agreement "
            "on a fixture set &#8212; it is not real-world detection accuracy.",
            positive_html + cite_html,
        ),
        render_chart_block(
            charts["if_comparison"],
            "The original Phase 2B Isolation Forest against the Phase 2D pipeline-aligned "
            "candidate, both scored on the same 24-observation frozen controlled cohort. "
            "The Phase 2D model is an <strong>unpromoted candidate artifact</strong>: it is not "
            "the deployed production model, and it did not meet every pre-frozen acceptance "
            "criterion. Controlled synthetic offline results only.",
            acc_html,
        ),
        render_chart_block(
            charts["latency"],
            "Per-packet latency for each assessment stage, from a controlled offline benchmark "
            "on a single Windows development host. These are in-process timings on "
            "pre-loaded packets &#8212; not network throughput, not line rate, not production "
            "capacity, and not validated on Raspberry Pi or any ARM64 target.",
            latency_def_html,
        ),
        render_chart_block(
            ts_chart,
            "Observed ranges of two model input features, comparing the cohorts the Phase 2B "
            "model was fitted on against the cohorts the real pipeline actually produces. "
            "Descriptive only: no feature, distribution or model parameter was modified to "
            "produce this view. Divergence here is the train/serve skew the Phase 2D work "
            "was undertaken to address.",
            cohort_note + finding_html,
        ),
    ]

    return """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CIPHER Demo Results</title>
<meta name="description" content="Controlled, synthetic, offline evaluation results for CIPHER, rendered from verified evaluation artifacts.">
<style>{css}</style>
</head>
<body>
<div class="wrap">

<header class="masthead">
  <div>
    <h1>CIPHER demo results</h1>
    <p class="sub">Rendered from the verified evaluation artifacts in
      <code>data/evaluation/research/</code>. Every figure below is read from those
      files at generation time.</p>
  </div>
  <button id="themebtn" class="themebtn" type="button">Dark mode</button>
</header>

<div class="evidence">{icon}<span>{cls} &#8212; NOT REAL-WORLD ACCURACY</span></div>

<div class="callout">
  <strong>How to read this page.</strong> Everything here was produced on fixed
  synthetic fixtures, offline, on one Windows development host. The classification
  figures measure <em>agreement with an a-priori external rubric</em> and
  <em>conformance to a frozen specification</em> &#8212; not detection performance against
  real network traffic. The Phase 2D Isolation Forest is an
  <strong>unpromoted candidate artifact</strong>, not the deployed production model.
  No figure on this page should be cited as real-world accuracy, production
  capacity, or a Raspberry&nbsp;Pi / ARM64 result.
</div>
{missing}

<section class="block">
  <h2>Headline metrics<span class="tag">{cls}</span></h2>
  <p class="sub" style="font-size:0.86rem">Each card names the artifact it was read
    from. A card reads &#8220;{na}&#8221; when its source value is absent.</p>
  <div class="cards">{cards}</div>
</section>

{blocks}

<section class="block" id="provenance">
  <h2>Data sources</h2>
  <p class="sub" style="font-size:0.86rem">The artifacts this page was built from,
    with their on-disk modification times and their own recorded evaluation
    timestamps. No measured value is hardcoded in the generator.</p>
  {prov}
</section>

<footer>
  Generated {generated} by <code>generate_demo_results.py</code> v{version} &#183;
  presentation and evaluation tooling only &#183; no third-party dependencies &#183;
  this page is fully self-contained and requires no network access.
</footer>

</div>
<script>{js}</script>
</body>
</html>
""".format(
        css=PAGE_CSS,
        icon=WARN_ICON,
        cls=EVIDENCE_CLASS,
        na=UNAVAILABLE,
        missing=missing_html,
        cards="".join(render_card(c) for c in cards),
        blocks="".join(blocks),
        prov=render_table(
            [
                "Artifact",
                "Status",
                "Recorded evaluation timestamp",
                "File modified",
                "Size",
                "Detail",
            ],
            prov_rows,
        ),
        generated=generated,
        version=GENERATOR_VERSION,
        js=THEME_JS,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Generate the CIPHER demo-results page and charts from the verified "
            "evaluation artifacts. Presentation tooling only; reads the project, "
            "writes only the output directory."
        )
    )
    parser.add_argument(
        "--out",
        default="demo_results",
        help="output directory, relative to the project root (default: demo_results)",
    )
    parser.add_argument(
        "--research-dir",
        default=None,
        help="override the directory holding the evaluation artifacts",
    )
    parser.add_argument(
        "--open",
        action="store_true",
        dest="open_browser",
        help="open the generated page in the default browser afterwards",
    )
    args = parser.parse_args(argv)

    research = Path(args.research_dir).resolve() if args.research_dir else RESEARCH_DIR
    out_dir = Path(args.out)
    if not out_dir.is_absolute():
        out_dir = PROJECT_ROOT / out_dir
    charts_dir = out_dir / "charts"
    charts_dir.mkdir(parents=True, exist_ok=True)

    print("CIPHER demo-results generator v{0}".format(GENERATOR_VERSION))
    print("  reading  : {0}".format(research))
    print("  writing  : {0}".format(out_dir))
    if not research.is_dir():
        print(
            "  warning  : research directory not found; every figure will render "
            '"{0}"'.format(UNAVAILABLE)
        )

    src = SourceSet(research)
    for entry in src.provenance:
        print(
            "  {0:<34} {1}{2}".format(
                entry["name"],
                entry["status"],
                "  ({0})".format(entry["detail"]) if entry["detail"] else "",
            )
        )

    pytest_baseline = read_pytest_baseline(README_PATH)
    if isinstance(pytest_baseline["value"], Missing):
        print("  pytest baseline: {0} ({1})".format(UNAVAILABLE, pytest_baseline["value"].reason))
    else:
        print("  pytest baseline: {0} (from {1}:{2})".format(
            pytest_baseline["value"], pytest_baseline["source"], pytest_baseline["line"]
        ))

    charts = {
        "qrs": build_chart_qrs(src),
        "if_comparison": build_chart_if_comparison(src),
        "latency": build_chart_latency(src),
        "train_serve": build_chart_train_serve(src),
    }
    cards = build_cards(src, pytest_baseline)

    written: list[Path] = []
    chart_files = {
        "qrs": "01_qrs_controlled_classification.svg",
        "if_comparison": "02_isolation_forest_2b_vs_2d.svg",
        "latency": "03_windows_latency_comparison.svg",
        "train_serve": "04_train_serve_feature_distribution.svg",
    }
    for key, filename in chart_files.items():
        path = charts_dir / filename
        path.write_text(charts[key]["svg"], encoding="utf-8")
        written.append(path)

    page = render_page(src, charts, cards)
    index = out_dir / "index.html"
    index.write_text(page, encoding="utf-8")
    written.append(index)

    print("\n  files written:")
    for path in written:
        print("    {0}  ({1:,} B)".format(_relpath(path), path.stat().st_size))

    unavailable = page.count(UNAVAILABLE)
    print(
        '\n  "{0}" placeholders on the page: {1}'.format(UNAVAILABLE, unavailable)
    )
    print("  open: {0}".format(index))

    if args.open_browser:
        webbrowser.open(index.as_uri())
    return 0


if __name__ == "__main__":
    sys.exit(main())
