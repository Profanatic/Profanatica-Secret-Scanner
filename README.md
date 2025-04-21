# Profanatica-Secret-Scanner
An advanced scanner for exposed secrets in web pages, APIs, and source code.

Key Features:
🔍 Automated Detection of:

API keys (AWS, Google, Stripe, etc.)

Access tokens (OAuth, JWT, Facebook, Twitter)

Credentials in URLs (username/password)

Private keys (RSA, DSA, EC, PGP)

Secrets in JSON, XML, and source code

📂 Structured Output:

Generates reports in profanatica_results/found_secrets.txt

Includes context where secrets were found

⚡ Performance Optimized:

Multi-threading support (Worker Threads)

Configurable timeout and automatic retry

Usage:
node scanner.js https://example.com
Ideal for:

Pentesters

Bug bounty hunters

DevSecOps teams

Developers checking for accidental leaks

License: Open for non-commercial use.

"Finding secrets before hackers do." 🔐

Technical Highlights:
✅ 30+ Built-in Detection Patterns
✅ Smart Validation (reduces false positives)
✅ Clean Console Reporting
✅ Lightweight & Fast

Note: Use responsibly and only on authorized targets.

Profanatica Secret Scanner - Prerequisites
To run the Profanatica Secret Scanner, ensure your system meets the following requirements:

1. Node.js & npm
Node.js (v14.x or higher)

npm (v6.x or higher) or yarn (optional)

📌 Installation Guide:

Windows/macOS/Linux: Download from nodejs.org

Verify installation:

node --version
npm --version

2. Dependencies
The tool requires the following npm packages:

axios (for HTTP requests)

fs & path (built-in Node.js modules)

worker_threads (for multi-threading, built-in since Node.js v12)

📌 Install dependencies automatically by running:

npm install
(If using the standalone script, dependencies are included.)

3. Permissions
Internet access (for scanning external URLs)

Write access (to save reports in ./profanatica_results/)

4. Supported OS
✅ Windows (10/11)
✅ Linux (Ubuntu/Debian, CentOS, etc.)
✅ macOS (Intel/Apple Silicon)

5. Optional (Recommended)
Git (to clone the repository if needed)

VS Code (or any code editor for debugging)

Quick Start
Install Node.js (if not already installed).

Download the scanner script.

Run:
node scanner.js https://example.com
Check results in ./profanatica_results/found_secrets.txt.

Note:
For large-scale scans, consider increasing Node.js memory limits:

node --max-old-space-size=4096 scanner.js https://example.com
Use responsibly and comply with all applicable laws.

🚀 Happy hunting!
