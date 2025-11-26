import asyncio
import aiohttp
import socket
import ssl
import json
import re
import argparse
import pandas as pd
from datetime import datetime
from bs4 import BeautifulSoup
import tldextract

# ================= CONFIG =================

TIMEOUT = 10
CONCURRENCY = 50
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
}


# ================= SUBDOMAIN SOURCES (Unchanged) =================

# (The existing functions from_crtsh, from_bufferover, from_hackertarget are kept here)
async def from_crtsh(domain):
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    subs = set()
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=TIMEOUT) as r:
                if r.status == 200:
                    data = await r.text()
                    for entry in json.loads(data):
                        name = entry.get("name_value", "")
                        for s in name.split("\n"):
                            if "*" not in s:
                                subs.add(s.strip())
    except:
        pass
    return subs


async def from_bufferover(domain):
    url = f"https://dns.bufferover.run/dns?q=.{domain}"
    subs = set()
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=TIMEOUT) as r:
                if r.status == 200:
                    data = await r.json()
                    for entry in data.get("FDNS_A", []):
                        s = entry.split(",")[-1]
                        subs.add(s.strip())
    except:
        pass
    return subs


async def from_hackertarget(domain):
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    subs = set()
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=TIMEOUT) as r:
                if r.status == 200:
                    text = await r.text()
                    for line in text.splitlines():
                        s = line.split(",")[0]
                        subs.add(s.strip())
    except:
        pass
    return subs

# ================= RESOLUTION + STATUS (Unchanged) =================

async def resolve_ip(host):
    try:
        return socket.gethostbyname(host)
    except:
        return None

async def fetch_info(session, url):
    # This function is slightly modified to capture a full dictionary for consistency
    # (ASN capture is removed as it wasn't in the original scan_host output, but can be added later)
    try:
        async with session.get(url, timeout=TIMEOUT, allow_redirects=True) as r:
            text = await r.text(errors="ignore")
            soup = BeautifulSoup(text, "html.parser")

            title = soup.title.string.strip() if soup.title and soup.title.string else "N/A"
            # server and tech headers are not used in the final report template, 
            # so they are omitted for simplicity, matching the report table.

            return r.status, title

    except Exception:
        return None, " "

async def scan_host(session, host):
    ip = await resolve_ip(host)

    https_url = f"https://{host}"
    http_url = f"http://{host}"

    status, title = await fetch_info(session, https_url)
    scheme = "https"

    if not status:
        status, title = await fetch_info(session, http_url)
        scheme = "http"

    return {
        "subdomain": host,
        "url": f"{scheme}://{host}",
        "ip": ip,
        "status_code": status,
        "title": title,
        "asn": "N/A" # Defaulting ASN to N/A for now, as it requires another API call.
    }


# ================= HTML REPORT (Slightly Simplified) =================
# The HTML generator is kept mostly the same, but it must handle the master list format.

from datetime import datetime

def generate_html(domain, results):

    # This generator now expects the clean, unique list of dictionaries
    # from build_master_list, which already handles normalization.
    
    live_count = sum(1 for r in results if r.get("status_code") is not None and r["status_code"] < 400)
    down_count = len(results) - live_count

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = f"""<!DOCTYPE html>
<html>
<head>
<title>ARCE Master Report - {domain}</title>
<style>
/* ... (CSS Styles remain the same) ... */
body {{
    font-family: Arial;
    background: #0f172a;
    color: #f8fafc;
    padding: 20px;
}}
h1 {{ color: #38bdf8; }}

input {{
    padding: 10px;
    width: 300px;
    margin-bottom: 20px;
}}

table {{
    border-collapse: collapse;
    width: 100%;
}}

th, td {{
    padding: 10px;
    border-bottom: 1px solid #334155;
}}

th {{
    background: #1e293b;
    cursor: pointer; /* Add pointer to show columns are clickable */
}}

tr:hover {{
    background: #1e293b;
}}

.badge {{
    display: inline-block;
    padding: 6px 12px;
    border-radius: 20px;
    margin-right: 10px;
}}

.green {{ background: #22c55e; color:black; }}
.red {{ background: #ef4444; color:black; }}
.blue {{ background: #0ea5e9; color:black; }}
.orange {{ background: #f97316; color:black; }}
.gray {{ background: #6b7280; color:black; }}
</style>

<script>
var sortDirection = {{}}; // State to track sort order for each column

function searchTable() {{
    var input = document.getElementById("search");
    var filter = input.value.toLowerCase();
    var rows = document.querySelectorAll("tbody tr");

    rows.forEach(row => {{
        if (row.innerText.toLowerCase().includes(filter)) {{
            row.style.display = "";
        }} else {{
            row.style.display = "none";
        }}
    }});
}}

function sortTable(n) {{
    var table, rows, switching, i, x, y, shouldSwitch;
    table = document.querySelector("table");
    switching = true;

    // Set initial direction to ascending if not set
    if (sortDirection[n] === undefined) {{
        sortDirection[n] = "asc";
    }} else if (sortDirection[n] === "asc") {{
        sortDirection[n] = "desc";
    }} else {{
        sortDirection[n] = "asc";
    }}
    
    var direction = sortDirection[n];

    /* Make a loop that will continue until no switching has been done: */
    while (switching) {{
        switching = false;
        rows = table.rows;
        /* Loop through all table rows (except the first, which contains table headers): */
        for (i = 1; i < (rows.length - 1); i++) {{
            shouldSwitch = false;
            
            // Get the two elements you want to compare, one from current row and one from the next
            x = rows[i].getElementsByTagName("TD")[n];
            y = rows[i + 1].getElementsByTagName("TD")[n];
            
            // Extract the sortable value
            var xValue = isNaN(x.innerHTML) ? x.innerHTML.toLowerCase() : Number(x.innerHTML);
            var yValue = isNaN(y.innerHTML) ? y.innerHTML.toLowerCase() : Number(y.innerHTML);

            // Special handling for the Status column (index 2)
            if (n === 2) {{
                // Convert "DOWN" to a high number (e.g., 999) so it appears at the end when sorting by code
                xValue = (xValue === 'down') ? 999 : Number(x.innerHTML);
                yValue = (yValue === 'down') ? 999 : Number(y.innerHTML);
            }}

            if (direction === "asc") {{
                if (xValue > yValue) {{
                    shouldSwitch = true;
                    break;
                }}
            }} else if (direction === "desc") {{
                if (xValue < yValue) {{
                    shouldSwitch = true;
                    break;
                }}
            }}
        }}
        if (shouldSwitch) {{
            /* If a switch has been marked, make the switch and set switching to true to continue the loop: */
            rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
            switching = true;
        }}
    }}
}}
</script>
</head>

<body>

<h1>🔍 ARCE Master Report for {domain}</h1>
<p>Generated at: {timestamp}</p>

<span class="badge blue">Total: {len(results)}</span>
<span class="badge green">Live: {live_count}</span>
<span class="badge red">Down: {down_count}</span>

<br><br>
<input type="text" id="search" onkeyup="searchTable()" placeholder="Search subdomain, title, IP...">

<table>
    <thead>
        <tr>
            <th onclick="sortTable(0)">Subdomain</th>
            <th onclick="sortTable(1)">URL</th>
            <th onclick="sortTable(2)">Status</th>
            <th onclick="sortTable(3)">Title</th>
            <th onclick="sortTable(4)">IP</th>
            <th onclick="sortTable(5)">ASN</th>
        </tr>
    </thead>
    <tbody>
"""

    for r in results:
        sub = r.get("subdomain", "N/A")
        url = r.get("url")
        status = r.get("status_code")
        title = r.get("title", "N/A")
        ip = r.get("ip", "N/A")
        asn = r.get("asn", "N/A")

        if status is None:
            status_text = "DOWN"
            status_color = "#6b7280"
            url_display = "N/A"
        else:
            status_text = str(status)

            if 200 <= status < 300:
                status_color = "#22c55e"
            elif 300 <= status < 400:
                status_color = "#f97316"
            elif 400 <= status < 500:
                status_color = "#ef4444"
            else:
                status_color = "#6b7280"

            url_display = f"<a href='{url}' target='_blank'>{url}</a>"

        # IMPORTANT: The status text is used as the sortable value, so we 
        # must ensure the content is the status code for number sorting.
        html += f"""
        <tr>
            <td>{sub}</td>
            <td>{url_display}</td>
            <td style="color:{status_color}; font-weight:bold;">{status_text}</td>
            <td>{title}</td>
            <td>{ip}</td>
            <td>{asn}</td>
        </tr>
"""

    html += """
    </tbody>
</table>

</body>
</html>
"""

    return html


# ================= HISTORY LOGIC =================

def load_history(history_file):
    """Loads the history file or returns a new structure."""
    try:
        with open(history_file, "r") as f:
            data = json.load(f)
            # Ensure it has the expected structure
            if "runs" not in data:
                data["runs"] = []
            return data
    except (FileNotFoundError, json.JSONDecodeError):
        return {"domain": "", "runs": []}


def save_history(history_file, history_data):
    """Saves the updated history to the file."""
    with open(history_file, "w") as f:
        json.dump(history_data, f, indent=4)


def build_master_list(history_data):
    """Aggregates and deduplicates results from all runs."""
    unique = {}

    # Iterate through runs in reverse to ensure the latest scan data overwrites older data
    for run in reversed(history_data["runs"]):
        # The 'subs' key contains the list of scan results (dictionaries)
        for entry in run.get("subs", []): 
            name = entry.get("subdomain")
            if name and name not in unique:
                # Add the entry to the unique list. 
                # Since we are iterating in reverse, the first time we see an entry is its most recent scan.
                unique[name] = entry

    # Return the aggregated list in alphabetical order by subdomain
    return sorted(list(unique.values()), key=lambda x: x['subdomain'])


# ================= RUNNER =================

async def run_single_scan(domain):
    """Performs a single complete subdomain scan."""
    print(f"[+] Starting subdomain enumeration for {domain}...")

    subs = set()
    tasks = [
        from_crtsh(domain),
        from_bufferover(domain),
        from_hackertarget(domain)
    ]

    results = await asyncio.gather(*tasks)
    for r in results:
        subs.update(r)

    # Filter and clean up the list of subdomains
    subs = sorted(list({s for s in subs if s.endswith(domain)}))
    print(f"[+] Found {len(subs)} unique subdomains from sources.")

    if not subs:
        return []

    print(f"[+] Starting concurrent scanning of {len(subs)} hosts (CONCURRENCY: {CONCURRENCY})")
    
    # Use a TCPConnector to respect the concurrency limit
    connector = aiohttp.TCPConnector(limit=CONCURRENCY, ssl=False)
    async with aiohttp.ClientSession(headers=HEADERS, connector=connector) as session:
        scans = await asyncio.gather(*[scan_host(session, s) for s in subs])

    # Filter out entries that have neither a status code nor an IP
    clean = [s for s in scans if s.get("status_code") or s.get("ip")]
    
    print(f"[+] Finished scan. {len(clean)} hosts returned data.")
    return clean


async def main_runner(domain, runs):
    """The main entry point for running multiple scans and generating the master report."""
    
    # Define file paths
    history_file = f"history_{domain}.json"
    master_report_file = f"ARCE_master_report_{domain}.html"

    # Load existing history
    history = load_history(history_file)
    history["domain"] = domain

    # Execute the requested number of runs
    for i in range(1, runs + 1):
        print("---" * 20)
        print(f"| RUN {i} of {runs} | Scan Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} |")
        print("---" * 20)
        
        # Perform the scan
        run_results = await run_single_scan(domain)
        
        # Prepare the run data structure for history
        run_data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "subs": run_results
        }
        
        # Append to history
        history["runs"].append(run_data)
        
        # Save history after each run (optional, but safer)
        save_history(history_file, history)

    print("\n" + "="*50)
    print(f"| Final Analysis | Aggregating {len(history['runs'])} Runs |")
    print("="*50)

    # 1. Build Master List (Deduplicate and use latest data)
    master_results = build_master_list(history)
    print(f"[+] Total UNIQUE Subdomains Found Across All Runs: {len(master_results)}")

    # 2. Generate Master HTML Report
    html = generate_html(domain, master_results)
    with open(master_report_file, "w", encoding="utf-8") as f:
        f.write(html)
        
    print(f"[+] Master Report saved as {master_report_file}")
    print(f"[+] History saved to {history_file}")


# ================= ENTRY =================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ReconX: Automated Subdomain Enumeration with History Tracking.")
    parser.add_argument("domain", type=str, help="The target domain (e.g., example.com)")
    parser.add_argument("--runs", type=int, default=1, help="Number of times to run the full scan (default: 1)")
    
    args = parser.parse_args()
    
    # Run the main runner function
    asyncio.run(main_runner(args.domain, args.runs))
