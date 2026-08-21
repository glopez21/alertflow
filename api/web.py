"""Server-rendered web dashboard for AlertFlow.

Serves a single read-only dashboard page at ``/`` plus a partial-refresh
endpoint used by the auto-reload timer. The dashboard renders alert
statistics, a filterable/paginated alert table, and expandable per-alert
detail (enrichment results, analyst notes).

The routes are intentionally exempt from API-key authentication (see
``auth._check_api_key``) because the dashboard is strictly read-only and
must be reachable from the homelab portal without distributing the API
key to browsers.

No template engine dependency: HTML is assembled in Python with all
interpolated values passed through ``html.escape``.
"""

import html
import json

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

from api.deps import get_store

router = APIRouter(tags=["web"])

PAGE_SIZE = 25

STATUS_FILTERS = [
    "Open",
    "In Progress",
    "Escalated",
    "Closed - FP",
    "Closed - Benign",
    "Closed - Responded",
    "Closed",
]

_SEVERITY_CLASS = {
    "P1": "sev-p1",
    "P2": "sev-p2",
    "P3": "sev-p3",
    "P4": "sev-p4",
}

_STATUS_CLASS = {
    "Open": "st-open",
    "In Progress": "st-progress",
    "Escalated": "st-escalated",
}

_PAGE_SHELL = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AlertFlow — SOC Alert Triage</title>
<style>
  :root {{
    --bg: #0f172a; --panel: #1e293b; --border: #334155;
    --text: #e2e8f0; --muted: #94a3b8; --accent: #38bdf8;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: var(--bg); color: var(--text);
    font-family: ui-sans-serif, system-ui, -apple-system, sans-serif;
    font-size: 14px; padding: 24px;
  }}
  .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }}
  header {{
    display: flex; align-items: center; justify-content: space-between;
    max-width: 1200px; margin: 0 auto 20px; flex-wrap: wrap; gap: 12px;
  }}
  header h1 {{
    font-size: 22px; letter-spacing: 0.5px;
  }}
  header h1 span {{ color: var(--accent); }}
  .controls {{ display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }}
  .controls label {{ color: var(--muted); font-size: 12px; display: flex; gap: 6px; align-items: center; }}
  input[type="search"] {{
    background: var(--panel); border: 1px solid var(--border); color: var(--text);
    border-radius: 8px; padding: 7px 12px; width: 220px; outline: none;
  }}
  input[type="search"]:focus {{ border-color: var(--accent); }}
  button, select {{
    background: var(--panel); border: 1px solid var(--border); color: var(--text);
    border-radius: 8px; padding: 7px 12px; cursor: pointer; font-size: 13px;
  }}
  button:hover {{ border-color: var(--accent); }}
  main {{ max-width: 1200px; margin: 0 auto; }}
  .cards {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 12px; margin-bottom: 20px;
  }}
  .card {{
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 12px; padding: 14px 16px;
  }}
  .card .num {{ font-size: 26px; font-weight: 700; }}
  .card .lbl {{ color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }}
  .card.c-accent .num {{ color: var(--accent); }}
  .card.c-red .num {{ color: #f87171; }}
  .card.c-amber .num {{ color: #fbbf24; }}
  .card.c-green .num {{ color: #34d399; }}
  table {{ width: 100%; border-collapse: collapse; }}
  .tablewrap {{
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 12px; overflow: hidden;
  }}
  th {{
    text-align: left; color: var(--muted); font-size: 11px; text-transform: uppercase;
    letter-spacing: 1px; padding: 10px 14px; border-bottom: 1px solid var(--border);
  }}
  td {{ padding: 9px 14px; border-bottom: 1px solid rgba(51,65,85,0.5); vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  tr.row:hover td {{ background: rgba(56,189,248,0.05); }}
  details summary {{ cursor: pointer; list-style: none; }}
  details summary::-webkit-details-marker {{ display: none; }}
  .chev {{ display: inline-block; transition: transform 0.15s; color: var(--muted); margin-right: 6px; }}
  details[open] .chev {{ transform: rotate(90deg); }}
  .badge {{
    display: inline-block; font-size: 11px; font-weight: 600; padding: 2px 8px;
    border-radius: 999px; white-space: nowrap;
  }}
  .sev-p1 {{ background: rgba(239,68,68,0.15); color: #f87171; }}
  .sev-p2 {{ background: rgba(251,191,36,0.15); color: #fbbf24; }}
  .sev-p3 {{ background: rgba(56,189,248,0.15); color: #38bdf8; }}
  .sev-p4 {{ background: rgba(148,163,184,0.15); color: #94a3b8; }}
  .st-open {{ background: rgba(52,211,153,0.12); color: #34d399; }}
  .st-progress {{ background: rgba(251,191,36,0.12); color: #fbbf24; }}
  .st-escalated {{ background: rgba(239,68,68,0.12); color: #f87171; }}
  .st-closed {{ background: rgba(148,163,184,0.12); color: #94a3b8; }}
  .title-cell {{ max-width: 420px; }}
  .muted {{ color: var(--muted); }}
  pre {{
    background: #0b1220; border: 1px solid var(--border); border-radius: 8px;
    padding: 10px; font-size: 12px; overflow-x: auto; margin-top: 8px;
    color: #cbd5e1; font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  }}
  .detail-grid {{ display: grid; grid-template-columns: 140px 1fr; gap: 4px 12px; margin-top: 8px; font-size: 13px; }}
  .detail-grid dt {{ color: var(--muted); }}
  .pager {{
    display: flex; gap: 10px; justify-content: space-between; align-items: center;
    max-width: 1200px; margin: 14px auto 0; color: var(--muted); font-size: 13px;
  }}
  .pager a {{ color: var(--accent); text-decoration: none; }}
  .pager a.disabled {{ color: var(--border); pointer-events: none; }}
  .empty {{ padding: 32px; text-align: center; color: var(--muted); }}
</style>
</head>
<body>
<header>
  <h1 class="mono">Alert<span>Flow</span> <span class="muted" style="font-size:13px">/ soc alert triage</span></h1>
  <div class="controls">
    <form method="get" action="/" style="display:flex; gap:10px;">
      <input type="search" name="q" placeholder="Search title / IOC / source" value="{q}">
      <select name="status">
        <option value="">All statuses</option>
        {status_options}
      </select>
      <button type="submit">Filter</button>
    </form>
    <label><input type="checkbox" id="auto" checked> auto-refresh</label>
  </div>
</header>
<main id="content">
{content}
</main>
<script>
const esc = s => s.replace(/[&<>"]/g, c => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}}[c]));
let params = location.search;
async function refresh() {{
  try {{
    const r = await fetch('/partials/content' + params);
    if (r.ok) document.getElementById('content').innerHTML = await r.text();
  }} catch (e) {{ /* transient */ }}
}}
setInterval(() => {{ if (document.getElementById('auto').checked) refresh(); }}, 15000);
</script>
</body>
</html>"""


def _status_chip(status: str) -> str:
    cls = _STATUS_CLASS.get(status, "st-closed")
    return f'<span class="badge {cls}">{html.escape(status)}</span>'


def _severity_badge(severity: str) -> str:
    cls = _SEVERITY_CLASS.get(severity, "sev-p4")
    return f'<span class="badge {cls}">{html.escape(severity)}</span>'


def _render_content(store, status_filter: str, q: str, offset: int) -> tuple[str, int]:
    """Render stats cards + alert table. Returns (html, total_matching)."""
    stats = store.stats()
    by_status = stats["by_status"]
    by_severity = stats["by_severity"]

    open_count = sum(by_status.get(s, 0) for s in ("Open", "In Progress", "Escalated"))
    cards = [
        ("c-accent", stats["total"], "Total Alerts"),
        ("c-red", by_severity.get("P1", 0), "P1 Critical"),
        ("c-green", open_count, "Active"),
        ("c-amber", by_status.get("Escalated", 0), "Escalated"),
        ("", by_status.get("Closed - FP", 0), "False Positives"),
    ]
    cards_html = "".join(
        f'<div class="card {cls}"><div class="num mono">{n}</div><div class="lbl">{lbl}</div></div>'
        for cls, n, lbl in cards
    )

    alerts, total = store.list_alerts(
        status=status_filter or None, limit=PAGE_SIZE, offset=offset, search=q or "", order="desc"
    )

    if not alerts:
        rows_html = '<tr><td colspan="6"><div class="empty">No alerts match the current filters.</div></td></tr>'
    else:
        parts = []
        for a in alerts:
            detail_extra = []
            if a.get("ioc"):
                detail_extra.append(f"<span class='muted'>IOC:</span> <span class='mono'>{html.escape(a['ioc'])}</span>")
            if a.get("analyst"):
                detail_extra.append(f"<span class='muted'>Analyst:</span> {html.escape(a['analyst'])}")
            if a.get("fp_reason"):
                detail_extra.append(f"<span class='muted'>FP Reason:</span> {html.escape(a['fp_reason'])}")

            enrichment = a.get("enrichment") or {}
            if enrichment and enrichment != {}:
                enrichment_json = html.escape(json.dumps(enrichment, indent=2, default=str))
                detail_extra.append(f"<pre>{enrichment_json}</pre>")

            notes = a.get("notes") or []
            if notes:
                notes_lines = "\n".join(
                    f"[{n.get('timestamp', '')[:19]}] {n.get('analyst', '')}: {n.get('note', '')}" for n in notes
                )
                detail_extra.append(f"<pre>{html.escape(notes_lines)}</pre>")

            title = html.escape(a["title"])
            summary = (
                f"<strong>{title}</strong>"
                f"<span class='muted'> — {html.escape(a['source'])}</span>"
            )
            if detail_extra:
                title_cell = (
                    "<details><summary class='mono'>"
                    f"<span class='chev'>&#9656;</span>{summary}</summary>"
                    f"<div style='margin-top:8px'>{' '.join(detail_extra)}</div></details>"
                )
            else:
                title_cell = f"<span class='mono'>{summary}</span>"

            created = html.escape(a["created_at"][:19])
            parts.append(
                f"<tr class='row'>"
                f"<td class='mono muted'>{a['id']}</td>"
                f"<td>{_severity_badge(a['severity'])}</td>"
                f"<td class='title-cell'>{title_cell}</td>"
                f"<td>{_status_chip(a['status'])}</td>"
                f"<td class='mono'>{created}</td>"
                f"<td class='mono'>{html.escape(a['source'])}</td>"
                f"</tr>"
            )
        rows_html = "".join(parts)

    table_html = (
        "<div class='tablewrap'><table>"
        "<thead><tr><th>ID</th><th>Severity</th><th>Title</th><th>Status</th>"
        "<th>Created</th><th>Source</th></tr></thead>"
        f"<tbody>{rows_html}</tbody></table></div>"
    )
    return cards_html + table_html, total


@router.get("/", response_class=HTMLResponse)
def dashboard(
    request: Request,
    status: str = "",
    q: str = "",
    page: int = 1,
    store=Depends(get_store),
):
    """Full dashboard page with filters and pagination."""
    status_filter = status if status in STATUS_FILTERS else ""
    query = (q or "").strip()
    page = max(page, 1)
    offset = (page - 1) * PAGE_SIZE

    content, total = _render_content(store, status_filter, query, offset)

    def page_link(p: int, label: str, disabled: bool) -> str:
        cls = "disabled" if disabled else ""
        href = "/?" + "&".join(
            part
            for part in [
                f"status={status_filter}" if status_filter else "",
                f"q={query}" if query else "",
                f"page={p}" if p != 1 else "",
            ]
            if part
        )
        return f'<a class="{cls}" href="{href or "/"}">{label}</a>'

    pager = (
        f"<div class='pager'>"
        f"{page_link(page - 1, '&larr; Prev', page <= 1)}"
        f"<span>{min(offset + 1, total) if total else 0}&ndash;{min(offset + PAGE_SIZE, total)} of {total} alerts</span>"
        f"{page_link(page + 1, 'Next &rarr;', offset + PAGE_SIZE >= total)}"
        f"</div>"
    )

    options = "".join(
        f'<option value="{html.escape(s)}"{" selected" if s == status_filter else ""}>{html.escape(s)}</option>'
        for s in STATUS_FILTERS
    )

    page_html = _PAGE_SHELL.format(q=html.escape(query), status_options=options, content=content + pager)
    return HTMLResponse(page_html)


@router.get("/partials/content", response_class=HTMLResponse)
def content_partial(
    request: Request,
    status: str = "",
    q: str = "",
    page: int = 1,
    store=Depends(get_store),
):
    """Content-only fragment for the dashboard auto-refresh timer."""
    status_filter = status if status in STATUS_FILTERS else ""
    query = (q or "").strip()
    page = max(page, 1)
    offset = (page - 1) * PAGE_SIZE
    content, _total = _render_content(store, status_filter, query, offset)
    return HTMLResponse(content)
