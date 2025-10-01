#!/usr/bin/env python3
"""
misp_ddos_reporter.py
Generates an interactive HTML report of MISP events (new/updated/deleted).
Config is loaded from .env (MISP_URL, MISP_KEY, MISP_VERIFY_SSL).
"""

from dotenv import load_dotenv
import os
import json
import argparse
import logging
import requests
from datetime import datetime, timezone
from deepdiff import DeepDiff
from jinja2 import Template

# Optional PyMISP (will be used if available)
try:
    from pymisp import PyMISP
    HAVE_PYMISP = True
except Exception:
    HAVE_PYMISP = False

# Defaults
DEFAULT_OUTPUT_DIR = "reports"
DEFAULT_SNAPSHOT_DIR = "snapshots"
DEFAULT_SNAPSHOT_NAME = "events_snapshot.json"
DEFAULT_REPORT_NAME = "misp_ddos_report.html"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# --- Helpers ---
def ensure_dir(path):
    os.makedirs(path, exist_ok=True)

def now_iso():
    return datetime.now(timezone.utc).isoformat()

# --- MISP Client ---
class MISPClient:
    def __init__(self, url, key, ssl_verify=True):
        self.url = url.rstrip('/')
        self.key = key
        self.ssl_verify = ssl_verify
        self.pymisp = None
        if HAVE_PYMISP:
            try:
                self.pymisp = PyMISP(self.url, self.key, ssl=self.ssl_verify, debug=False)
            except Exception as e:
                logging.warning("PyMISP init failed: %s (falling back to REST)", e)
                self.pymisp = None

        self.headers = {
            'Accept': 'application/json',
            'Authorization': self.key,
            'Content-type': 'application/json'
        }

    def fetch_events(self, org=None, tags=None, last=None, limit=1000):
        """
        Fetch events from MISP. Returns a list of event dicts.
        Tries PyMISP when available; falls back to /events/restSearch.
        """
        params = {}
        if org:
            params['org'] = org
        if tags:
            params['tags'] = ','.join(tags) if isinstance(tags, (list, tuple)) else tags
        if last:
            params['last'] = last

        # Try PyMISP first
        if self.pymisp:
            try:
                res = self.pymisp.search(controller='events', **params)
                events = []
                if isinstance(res, dict) and 'response' in res:
                    for item in res['response']:
                        events.append(item.get('Event') or item)
                elif isinstance(res, list):
                    for item in res:
                        events.append(item.get('Event') if isinstance(item, dict) and 'Event' in item else item)
                return events
            except Exception as e:
                logging.warning("PyMISP search failed: %s (falling back to REST)", e)

        # Fallback: REST endpoint
        url = f"{self.url}/events/restSearch"
        payload = {"returnFormat": "json", "limit": limit}
        payload.update(params)
        try:
            r = requests.post(url, headers=self.headers, json=payload, verify=self.ssl_verify, timeout=30)
            r.raise_for_status()
            data = r.json()
            events = []
            if isinstance(data, dict) and 'response' in data:
                for item in data['response']:
                    events.append(item.get('Event') or item)
            return events
        except Exception as e:
            logging.error("REST fetch failed: %s", e)
            return []

# --- Snapshot helpers ---
def load_snapshot(snapshot_dir, snapshot_name):
    ensure_dir(snapshot_dir)
    path = os.path.join(snapshot_dir, snapshot_name)
    if not os.path.isfile(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except Exception as e:
            logging.warning("Failed to load snapshot %s: %s", path, e)
            return {}

def save_snapshot(snapshot_dir, data, snapshot_name):
    ensure_dir(snapshot_dir)
    path = os.path.join(snapshot_dir, snapshot_name)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

# --- Event canonicalization & diffs ---
def key_event(ev):
    return str(ev.get('id') or ev.get('uuid') or ev.get('ID') or ev.get('event_id') or '')

def slim_event(ev):
    """
    Produce a canonical, small dict for comparing events.
    """
    e = {
        'id': ev.get('id'),
        'uuid': ev.get('uuid'),
        'info': ev.get('info'),
        'date': ev.get('date'),
        'timestamp': ev.get('timestamp'),
        'org': ev.get('Org') or ev.get('org'),
        'publish_timestamp': ev.get('publish_timestamp')
    }

    # Attributes
    attrs = []
    for a in ev.get('Attribute', []) or ev.get('attributes', []) or []:
        attrs.append({
            'type': a.get('type'),
            'category': a.get('category'),
            'value': a.get('value'),
            'to_ids': a.get('to_ids'),
            'uuid': a.get('uuid')
        })
    e['attributes'] = sorted(attrs, key=lambda x: (x.get('type') or '', str(x.get('value') or '')))

    # Tags
    tags = []
    for t in ev.get('Tag', []) or ev.get('tags', []) or []:
        if isinstance(t, dict):
            if 'name' in t:
                tags.append(t['name'])
            elif 'Tag' in t and isinstance(t['Tag'], dict) and 'name' in t['Tag']:
                tags.append(t['Tag']['name'])
        elif isinstance(t, str):
            tags.append(t)
    e['tags'] = sorted(list(set(tags)))
    return e

def compute_changes(old_snapshot, new_events):
    """
    old_snapshot: dict keyed by event key -> slim_event
    new_events: list of full event dicts
    """
    new_map = {}
    for ev in new_events:
        k = key_event(ev)
        if not k:
            k = str(ev.get('uuid') or ev.get('id') or '')
        new_map[k] = slim_event(ev)

    old_map = old_snapshot or {}

    new_keys = set(new_map.keys())
    old_keys = set(old_map.keys())

    created = [new_map[k] for k in (new_keys - old_keys)]
    deleted = [old_map[k] for k in (old_keys - new_keys)]

    updated = []
    for k in (new_keys & old_keys):
        before = old_map[k]
        after = new_map[k]
        dd = DeepDiff(before, after, ignore_order=True)
        if dd:
            try:
                # Ensure JSON-safe diff
                diff_dict = json.loads(json.dumps(dd.to_dict(), default=str))
            except Exception:
                diff_dict = {"error": str(dd)}
            updated.append({
                'id': k,
                'diff': diff_dict,
                'before': before,
                'after': after
            })

    return {'created': created, 'deleted': deleted, 'updated': updated, 'new_map': new_map}

# --- Interactive HTML template ---
HTML_TMPL = """<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<title>MISP DDoS Events Report - {{ ts }}</title>
<style>
body{font-family:Arial,Helvetica,sans-serif;margin:18px;background:#fafafa;color:#111;}
h1{font-size:22px;margin-bottom:6px;}
.card{border:1px solid #ccc;padding:12px;margin:12px 0;border-radius:8px;background:#fff;}
.small{font-size:0.9em;color:#555;}
pre{background:#f7f7f7;padding:8px;border-radius:6px;overflow:auto;max-height:360px;}
.toggle{cursor:pointer;color:#0366d6;text-decoration:underline;}
.badge{padding:2px 6px;border-radius:12px;font-size:0.85em;background:#eee;margin-right:6px;}
.tab-btn{padding:6px 10px;margin-right:6px;border:1px solid #ccc;border-radius:4px;background:#eee;cursor:pointer;}
.tab-btn.active{background:#0366d6;color:#fff;}
.tab-content{display:none;margin-top:10px;}
.tab-content.active{display:block;}
.search-input{padding:8px 10px;font-size:14px;width:360px;margin-bottom:12px;border:1px solid #ccc;border-radius:6px;}
.summary{margin-bottom:14px;}
</style>
<script>
function toggle(id){
  var e = document.getElementById(id);
  if(!e) return;
  var cur = (e.style.display === '' || e.style.display === 'none') ? 'none' : e.style.display;
  if(cur === 'none' || cur === '') e.style.display = 'block';
  else e.style.display = 'none';
}
function showTab(id, tab){
  ['before','after','diff'].forEach(x=>{
    var c = document.getElementById(x+'_'+id);
    var b = document.getElementById('btn_'+x+'_'+id);
    if(c) c.classList.remove('active');
    if(b) b.classList.remove('active');
  });
  var content = document.getElementById(tab+'_'+id);
  var button = document.getElementById('btn_'+tab+'_'+id);
  if(content) content.classList.add('active');
  if(button) button.classList.add('active');
}
function filterEvents(){
  var q = document.getElementById('search').value.toLowerCase();
  document.querySelectorAll('.card').forEach(function(c){
    c.style.display = (c.innerText.toLowerCase().includes(q) ? 'block' : 'none');
  });
}
</script>
</head>
<body>
<h1>MISP DDoS Events Report</h1>
<div class="small">Generated: {{ ts }}</div>

<div class="summary card small">
  <strong>Summary</strong>
  <div style="margin-top:6px;">
    New <span class="badge">{{ counts.created }}</span>
    Updated <span class="badge">{{ counts.updated }}</span>
    Deleted <span class="badge">{{ counts.deleted }}</span>
    Total <span class="badge">{{ counts.total }}</span>
  </div>
</div>

<input id="search" class="search-input" onkeyup="filterEvents()" placeholder="Search events (id, info, tags, attribute values)"/>

{% if created %}
<h2>New ({{ created|length }})</h2>
{% for e in created %}
<div class="card">
  <strong>{{ e.info or '(no info)' }}</strong>
  <div class="small">id: {{ e.id or 'n/a' }} | date: {{ e.date or 'n/a' }} | tags: {{ e.tags|default([])|join(', ') }}</div>
  <div style="margin-top:8px;">
    <a href="#" onclick="toggle('details_new_{{ loop.index0 }}');return false;" class="toggle">Details</a>
  </div>
  <div id="details_new_{{ loop.index0 }}" style="display:none;margin-top:8px;"><pre>{{ e | tojson(indent=2) }}</pre></div>
</div>
{% endfor %}
{% endif %}

{% if updated %}
<h2>Updated ({{ updated|length }})</h2>
{% for u in updated %}
<div class="card">
  <strong>{{ u.after.info or '(no info)' }}</strong> <span class="small">id: {{ u.id }}</span>
  <div style="margin-top:8px;">
    <button id="btn_before_{{ loop.index0 }}" class="tab-btn active" onclick="showTab('{{ loop.index0 }}','before')">Before</button>
    <button id="btn_after_{{ loop.index0 }}" class="tab-btn" onclick="showTab('{{ loop.index0 }}','after')">After</button>
    <button id="btn_diff_{{ loop.index0 }}" class="tab-btn" onclick="showTab('{{ loop.index0 }}','diff')">Diff</button>
  </div>
  <div id="before_{{ loop.index0 }}" class="tab-content active" style="display:block;margin-top:10px;"><pre>{{ u.before | tojson(indent=2) }}</pre></div>
  <div id="after_{{ loop.index0 }}" class="tab-content" style="margin-top:10px;"><pre>{{ u.after | tojson(indent=2) }}</pre></div>
  <div id="diff_{{ loop.index0 }}" class="tab-content" style="margin-top:10px;"><pre>{{ u.diff | tojson(indent=2) }}</pre></div>
</div>
{% endfor %}
{% endif %}

{% if deleted %}
<h2>Deleted ({{ deleted|length }})</h2>
{% for e in deleted %}
<div class="card">
  <strong>{{ e.info or '(no info)' }}</strong> <span class="small">id: {{ e.id or 'n/a' }}</span>
  <div style="margin-top:8px;"><pre>{{ e | tojson(indent=2) }}</pre></div>
</div>
{% endfor %}
{% endif %}

<hr>
<div class="small">Interactive report produced by misp_ddos_reporter.py</div>
</body>
</html>
"""

# --- Render & write report ---
def generate_html(out_path, changes, ts):
    counts = {
        'created': len(changes['created']),
        'updated': len(changes['updated']),
        'deleted': len(changes['deleted']),
        'total': len(changes.get('new_map', {}))
    }
    html = Template(HTML_TMPL).render(
        ts=ts,
        created=changes['created'],
        updated=changes['updated'],
        deleted=changes['deleted'],
        counts=counts
    )
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
    return out_path

# --- Main CLI ---
def main():
    load_dotenv()  # loads .env from cwd by default
    misp_url = os.getenv("MISP_URL")
    misp_key = os.getenv("MISP_KEY")
    ssl_verify = os.getenv("MISP_VERIFY_SSL", "true").lower() == "true"

    if not misp_url or not misp_key:
        logging.error("Missing MISP_URL or MISP_KEY in environment (.env). Aborting.")
        raise SystemExit(2)

    parser = argparse.ArgumentParser(description="MISP DDoS reporter (reads MISP_URL & MISP_KEY from .env)")
    parser.add_argument("--tags", nargs="*", help="Optional tag filters (e.g., ddos, botnet)")
    parser.add_argument("--org", help="Optional org shortname to restrict to")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--snapshot-dir", default=DEFAULT_SNAPSHOT_DIR)
    parser.add_argument("--snapshot-name", default=DEFAULT_SNAPSHOT_NAME)
    parser.add_argument("--report-name", default=DEFAULT_REPORT_NAME)
    parser.add_argument("--limit", type=int, default=1000)
    args = parser.parse_args()

    client = MISPClient(misp_url, misp_key, ssl_verify=ssl_verify)

    ensure_dir(args.output_dir)
    ensure_dir(args.snapshot_dir)

    old_snapshot = load_snapshot(args.snapshot_dir, args.snapshot_name)

    logging.info("Fetching events from MISP...")
    events = client.fetch_events(org=args.org, tags=args.tags, last=None, limit=args.limit)
    logging.info("Fetched %d events", len(events))

    changes = compute_changes(old_snapshot, events)
    out_path = os.path.join(args.output_dir, args.report_name)
    generate_html(out_path, changes, now_iso())

    save_snapshot(args.snapshot_dir, changes['new_map'], args.snapshot_name)

    logging.info("Report written to: %s", out_path)
    logging.info("Created: %d  Updated: %d  Deleted: %d",
                 len(changes['created']), len(changes['updated']), len(changes['deleted']))

if __name__ == "__main__":
    main()
