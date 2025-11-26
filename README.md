**ARCE: Archive, Reconnaissance, Consolidate, Enumerate**

ARCE is a powerful, asynchronous reconnaissance tool designed to go beyond a single scan. It automates the process of finding subdomains from multiple passive sources, actively checking their status, and—crucially—maintaining a persistent history of results for comparison and master reporting.

**✨ Features**

**Asynchronous Speed:** Utilizes asyncio and aiohttp for high-speed, concurrent scanning of thousands of hosts.

**Multi-Source Enumeration:** Gathers subdomains from popular external sources like crt.sh, BufferOver, and HackerTarget to maximize discovery.

**Historical Tracking:** Stores results from every scan run in a domain-specific JSON file (history_{domain}.json).

**Result Consolidation:** Aggregates data from all historical runs, deduplicates entries, and uses the most recent data for the final report.

**Master HTML Report:** Generates a single, clean, searchable, and sortable HTML report showing the final, consolidated view of all unique subdomains ever found.

**🚀 Installation and Setup**

**Prerequisites**

Python 3.8+

**Install Dependencies**

ARCE relies on several external Python libraries for core functionality:

pip install aiohttp beautifulsoup4 pandas tldextract


**⚙️ Usage**

ARCE is run from the command line, requiring the target domain as the first argument.

Basic Single-Run Scan

To run a single scan against a domain:

python arce.py target.com


Running Multiple Scans (Archiving History)

To run the scan multiple times sequentially (e.g., 3 times) to populate your history log:

python arce.py target.com --runs 3


Each run will update the history_target.com.json file and then generate a new master report based on the combined history.

**💾 Outputs**

After running ARCE, two main files will be generated in the current directory:

history_target.com.json

Purpose: The persistent database storing every scan result.

Structure: Contains a top-level "runs" array, where each object represents a timestamped execution of the scanner.

ARCE_master_report_target.com.html

Purpose: The final, clean, human-readable report.

Contents: A searchable, sortable table that shows the unique subdomains found, their latest status code, title, and IP. Clicking the Status column header allows you to sort by status code (live sites first, followed by down sites).

**🧩 How Consolidation Works**

When you run ARCE with --runs N, the tool:

Executes the full scan $N$ times.

Loads the existing history_{domain}.json.

The build_master_list function processes the entire history log.

If blog.target.com was found in Run 1 with Status 404, and then in Run 3 with Status 200, the final HTML report will show the latest data: Status 200. This ensures your master report is always up-to-date.
