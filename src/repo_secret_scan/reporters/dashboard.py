"""Self-contained interactive HTML dashboard (requires the ``dashboard`` extra)."""

from __future__ import annotations

import html
import json
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..dataset import Dataset
from ..models import Severity
from .base import ORG_REPORTERS

# Severity is an urgency state: fixed status colours, always shown with a text label.
SEVERITY_COLORS = {
    "critical": "#d03b3b",
    "high": "#ec835a",
    "medium": "#fab219",
    "low": "#a3a29b",
    "info": "#dcdbd4",
}
SERIES = "#2a78d6"
INK, INK_2, MUTED, GRID, SURFACE = "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#fcfcfb"


def _layout(title: str, height: int) -> dict[str, Any]:
    return dict(
        title=dict(text=title, x=0, xanchor="left", font=dict(size=15, color=INK)),
        height=height,
        margin=dict(l=10, r=20, t=50, b=70),
        paper_bgcolor=SURFACE,
        plot_bgcolor=SURFACE,
        font=dict(family='system-ui, -apple-system, "Segoe UI", sans-serif', size=12, color=INK_2),
        xaxis=dict(gridcolor=GRID, zeroline=False, linecolor=GRID, tickfont=dict(color=MUTED)),
        yaxis=dict(gridcolor=GRID, zeroline=False, linecolor=GRID, tickfont=dict(color=INK_2), automargin=True),
        legend=dict(orientation="h", yanchor="top", y=-0.12, xanchor="left", x=0, traceorder="normal"),
        barcornerradius=4,
        bargap=0.35,
        hoverlabel=dict(bgcolor="white", font=dict(color=INK)),
    )


def _figures(dataset: Dataset, top_n: int) -> list[Any]:
    import plotly.graph_objects as go

    open_secrets = [s for s in dataset.secrets if not s["suppressed"]]
    figures = []

    # Open secrets per repository, stacked by severity; most urgent repositories first.
    by_repo_sev = Counter((s["repo"], s["severity"]) for s in open_secrets)
    repos = {s["repo"] for s in open_secrets}
    urgency = lambda r: tuple(-by_repo_sev[(r, sev.value)] for sev in Severity)  # noqa: E731
    top_repos = sorted(repos, key=lambda r: (urgency(r), r))[:top_n][::-1]
    owners = {r.split("/", 1)[0] for r in top_repos}
    labels = [r.split("/", 1)[-1] for r in top_repos] if len(owners) == 1 else top_repos
    fig = go.Figure()
    for sev in Severity:
        counts = [by_repo_sev[(r, sev.value)] for r in top_repos]
        if not any(counts):
            continue
        fig.add_bar(
            y=labels, x=counts, name=sev.value, orientation="h",
            marker=dict(color=SEVERITY_COLORS[sev.value], line=dict(color=SURFACE, width=1)),
            hovertemplate="%{y}<br>" + sev.value + ": %{x}<extra></extra>",
        )
    fig.update_layout(**_layout(f"Open secrets by repository (top {len(top_repos)} by severity)", 150 + 22 * len(top_repos)), barmode="stack")
    figures.append(fig)

    # Detectors, counted as distinct secrets.
    rules = Counter(r for s in open_secrets for r in s["rules"].split(";") if r)
    top_rules = rules.most_common(top_n)[::-1]
    fig = go.Figure(go.Bar(
        y=[r for r, _ in top_rules], x=[c for _, c in top_rules], orientation="h", marker_color=SERIES,
        hovertemplate="%{y}: %{x} secrets<extra></extra>",
    ))
    fig.update_layout(**_layout("Most frequent detectors (distinct open secrets, all severities)", 120 + 22 * len(top_rules)))
    figures.append(fig)

    # Which scanners found each secret.
    agreement = Counter(s["scanners"].replace(";", " + ") for s in open_secrets).most_common()[::-1]
    fig = go.Figure(go.Bar(
        y=[k for k, _ in agreement], x=[v for _, v in agreement], orientation="h", marker_color=SERIES,
        text=[v for _, v in agreement], textposition="outside", textfont=dict(color=INK_2),
        hovertemplate="%{y}: %{x} secrets<extra></extra>",
    ))
    fig.update_layout(**_layout("Scanner agreement", 120 + 40 * len(agreement)))
    figures.append(fig)

    # When secrets were first committed.
    years = Counter(s["first_seen"][:4] for s in open_secrets if s["first_seen"])
    xs = sorted(years)
    fig = go.Figure(go.Bar(x=xs, y=[years[y] for y in xs], marker_color=SERIES, hovertemplate="%{x}: %{y} secrets<extra></extra>"))
    fig.update_layout(**_layout("Year each open secret was first committed", 320))
    figures.append(fig)
    return figures


_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
:root {{ color-scheme: light; --ink:#0b0b0b; --ink2:#52514e; --muted:#898781; --grid:#e1e0d9; --surface:#fcfcfb; --plane:#f9f9f7; }}
body {{ margin:0; background:var(--plane); color:var(--ink); font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif; }}
main {{ max-width:1200px; margin:0 auto; padding:24px 16px 64px; }}
h1 {{ font-size:22px; margin:0 0 4px; }} .sub {{ color:var(--ink2); margin:0 0 20px; }}
.tiles {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:12px; margin-bottom:20px; }}
.tile {{ background:var(--surface); border:1px solid rgba(11,11,11,.1); border-radius:8px; padding:12px 14px; }}
.tile .v {{ font-size:28px; font-weight:600; }} .tile .k {{ color:var(--ink2); }}
.charts {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(460px,1fr)); gap:12px; }}
.card {{ background:var(--surface); border:1px solid rgba(11,11,11,.1); border-radius:8px; padding:8px; min-width:0; }}
.filters {{ display:flex; flex-wrap:wrap; gap:8px; margin:24px 0 8px; align-items:center; }}
.filters input, .filters select {{ font:inherit; padding:6px 8px; border:1px solid var(--grid); border-radius:6px; background:white; }}
.tablewrap {{ overflow-x:auto; background:var(--surface); border:1px solid rgba(11,11,11,.1); border-radius:8px; }}
table {{ border-collapse:collapse; width:100%; font-variant-numeric:tabular-nums; }}
th, td {{ text-align:left; padding:6px 8px; border-bottom:1px solid var(--grid); vertical-align:top; }}
th {{ position:sticky; top:0; background:var(--surface); cursor:pointer; white-space:nowrap; }}
td code {{ font-size:12px; white-space:nowrap; }} td.path {{ max-width:360px; overflow-wrap:anywhere; }} .sev {{ display:inline-flex; gap:6px; align-items:center; white-space:nowrap; }}
.dot {{ width:10px; height:10px; border-radius:50%; display:inline-block; }}
.warn {{ color:#d03b3b; font-weight:600; }}
@media (max-width:520px) {{ .charts {{ grid-template-columns:1fr; }} }}
</style></head><body><main>
<h1>{title}</h1>
<p class="sub">Generated {generated}. <span class="warn">Confidential</span> — locates credentials; do not publish.</p>
<div class="tiles">{tiles}</div>
<div class="charts">{charts}</div>
<div class="filters">
  <strong>Secrets</strong>
  <input id="q" type="search" placeholder="Filter repo, detector, path…" aria-label="Filter">
  <select id="sev" aria-label="Minimum severity">
    <option value="4">all severities</option><option value="0">critical</option><option value="1">high+</option>
    <option value="2" selected>medium+</option><option value="3">low+</option></select>
  <label><input id="head" type="checkbox"> only still in HEAD</label>
  <label><input id="supp" type="checkbox"> include suppressed</label>
  <span id="count" class="sub" style="margin:0"></span>
</div>
<div class="tablewrap"><table><thead><tr>
<th data-k="severity">Severity</th><th data-k="repo">Repo</th><th data-k="rules">Detectors</th><th data-k="preview">Preview</th>
<th data-k="in_head">In HEAD</th><th data-k="occurrences">Hits</th><th data-k="location">Where</th><th data-k="first_seen">First seen</th><th data-k="secret_hash">Hash</th>
</tr></thead><tbody id="rows"></tbody></table></div>
</main>
<script>
const DATA = {data};
const RANK = {{critical:0, high:1, medium:2, low:3, info:4}};
const COLORS = {colors};
let sortKey = "severity", sortDir = 1;
const esc = s => String(s ?? "").replace(/[&<>"]/g, c => ({{"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}}[c]));
function render() {{
  const q = document.getElementById("q").value.toLowerCase();
  const maxRank = +document.getElementById("sev").value;
  const head = document.getElementById("head").checked, supp = document.getElementById("supp").checked;
  let rows = DATA.filter(r => RANK[r.severity] <= maxRank && (!head || r.in_head) && (supp || !r.suppressed)
    && (!q || [r.repo, r.rules, r.paths, r.secret_hash, r.tags].join(" ").toLowerCase().includes(q)));
  rows.sort((a, b) => {{
    const va = sortKey === "severity" ? RANK[a.severity] : a[sortKey], vb = sortKey === "severity" ? RANK[b.severity] : b[sortKey];
    return (va > vb ? 1 : va < vb ? -1 : 0) * sortDir;
  }});
  document.getElementById("count").textContent = rows.length + " of " + DATA.length;
  document.getElementById("rows").innerHTML = rows.slice(0, 2000).map(r => `<tr>
    <td><span class="sev"><span class="dot" style="background:${{COLORS[r.severity]}}"></span>${{r.severity}}</span></td>
    <td>${{esc(r.repo)}}</td><td>${{esc(r.rules).replaceAll(";", "<br>")}}</td><td><code>${{esc(r.preview)}}</code></td>
    <td>${{r.in_head ? "yes" : "history"}}</td><td>${{r.occurrences}}</td>
    <td class="path">${{r.link ? `<a href="${{esc(r.link)}}">${{esc(r.location)}}</a>` : esc(r.location)}}${{r.path_count > 1 ? ` (+${{r.path_count - 1}})` : ""}}</td>
    <td>${{esc((r.first_seen || "").slice(0, 10))}}</td><td><code title="${{esc(r.secret_hash)}}">${{esc(r.secret_hash.slice(0, 12))}}</code></td></tr>`).join("");
}}
document.querySelectorAll("th").forEach(th => th.addEventListener("click", () => {{
  sortDir = sortKey === th.dataset.k ? -sortDir : 1; sortKey = th.dataset.k; render();
}}));
["q", "sev", "head", "supp"].forEach(id => document.getElementById(id).addEventListener("input", render));
render();
// Charts render as the page streams in, before sibling cards exist; re-fit them to the final grid.
window.addEventListener("load", () => document.querySelectorAll(".js-plotly-plot").forEach(d => Plotly.Plots.resize(d)));
</script></body></html>
"""


@ORG_REPORTERS.register("dashboard")
@dataclass
class DashboardReporter:
    filename: str = "dashboard.html"
    top_n: int = 25

    def write(self, dataset: Dataset, out_dir: Path, title: str) -> None:
        try:
            import plotly.io as pio
        except ImportError as exc:
            raise RuntimeError("the dashboard report needs plotly: pip install 'repo-secret-scan[dashboard]'") from exc

        open_secrets = [s for s in dataset.secrets if not s["suppressed"]]
        failed = sum(1 for r in dataset.repos if r["status"] not in ("ok", "empty"))
        tiles = [
            (len(dataset.repos), "repositories scanned"),
            (len(open_secrets), "distinct open secrets"),
            (sum(1 for s in open_secrets if s["in_head"]), "still on default branch"),
            (sum(1 for s in open_secrets if s["severity"] in ("critical", "high")), "critical or high"),
            (failed, "repos with scan problems"),
        ]
        charts = []
        for i, fig in enumerate(_figures(dataset, self.top_n)):
            charts.append('<div class="card">' + pio.to_html(
                fig, full_html=False, include_plotlyjs=(i == 0), default_width="100%",
                config={"displaylogo": False, "responsive": True},
            ) + "</div>")
        columns = ["severity", "repo", "rules", "preview", "in_head", "occurrences", "location", "path_count", "paths", "first_seen", "secret_hash", "link", "suppressed", "tags"]
        data = json.dumps([{k: s[k] for k in columns} for s in dataset.secrets]).replace("</", "<\\/")
        page = _PAGE.format(
            title=html.escape(title),
            generated=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            tiles="".join(f'<div class="tile"><div class="v">{v}</div><div class="k">{k}</div></div>' for v, k in tiles),
            charts="".join(charts),
            data=data,
            colors=json.dumps(SEVERITY_COLORS),
        )
        (out_dir / self.filename).write_text(page)
