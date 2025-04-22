🔐 Profanatica-Secret-Scanner

An advanced scanner for exposed secrets in web pages, APIs, and source code.

"Finding secrets before hackers do."

🔍 Key Features
✅ Automated Detection of:
API keys (AWS, Google, Stripe, etc.)

Access tokens (OAuth, JWT, Facebook, Twitter)

Credentials in URLs (username/password)

Private keys (RSA, DSA, EC, PGP)

Secrets in JSON, XML, and source code

📂 Structured Output:
Generates reports in ./profanatica_results/found_secrets.txt

Includes context where secrets were found

⚡ Performance Optimized:
Multi-threading support (via Worker Threads)

Configurable timeout and automatic retry

🚀 Usage

node scanner.js https://example.com
👥 Ideal for:

Pentesters

Bug bounty hunters

DevSecOps teams

Developers checking for accidental leaks

📜 License
Open for non-commercial use.

⚠️ Use responsibly and only on authorized targets.

🛠️ Technical Highlights
✅ 30+ Built-in Detection Patterns

✅ Smart Validation (reduces false positives)

✅ Clean Console Reporting

✅ Lightweight & Fast

📦 Prerequisites
To run the Profanatica Secret Scanner, make sure you have:

Node.js & npm
Node.js (v14.x or higher)

npm (v6.x or higher) or yarn (optional)

🧰 Installation Guide
Windows / macOS / Linux:
Download Node.js from nodejs.org

Verify installation:

node --version
npm --version
Install dependencies:

npm install
(If using the standalone script, dependencies are included.)

📁 Dependencies
axios (for HTTP requests)

fs & path (built-in Node.js modules)

worker_threads (built-in since Node.js v12)

🛡️ Permissions Required
Internet access (for scanning external URLs)

Write access (to save reports in ./profanatica_results/)

💻 Supported OS
✅ Windows (10/11)

✅ Linux (Ubuntu/Debian, CentOS, etc.)

✅ macOS (Intel / Apple Silicon)

🧩 Optional (Recommended)
Git (to clone the repository if needed)

VS Code (or any code editor for debugging)

⚡ Quick Start
Install Node.js (if not already installed).

Download the scanner script.

Run:


node scanner.js https://example.com
Check the results in:


./profanatica_results/found_secrets.txt
🧠 Pro Tip
For large-scale scans, increase the Node.js memory limit:


node --max-old-space-size=4096 scanner.js https://example.com

🎯 Reminder
Use this tool responsibly and always comply with applicable laws.
Unauthorized scanning is strictly prohibited.

🚀 Happy Hunting!
