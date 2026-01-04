Chat AI itnerattiva dove puoi chiedere qualsiasi cosa...
e l'AI ti ropsonde.. usandi text to cypher o facnedo anche attacchhi reali, o anche solo domande informative sul recon o precedenti attacchi.

# RedAmon - Gap Analysis & Enhancement Roadmap

## Executive Summary

This document provides a comprehensive gap analysis of RedAmon's current capabilities versus a fully automated reconnaissance and vulnerability testing system. It identifies missing modules for **endpoint discovery**, **vulnerability testing**, **exposed asset discovery**, and **user enumeration**.

---

## Current RedAmon Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        CURRENT REDAMON PIPELINE                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   domain_discovery ──► port_scan ──► http_probe ──► resource_enum ──► vuln_scan ──► github
│         │                  │              │              │               │          │
│         │                  │              │              │               │          │
│    ┌────▼────┐       ┌────▼────┐    ┌────▼────┐    ┌────▼────┐     ┌────▼────┐  ┌──▼──┐
│    │  WHOIS  │       │  Naabu  │    │  httpx  │    │ Katana  │     │ Nuclei  │  │ Git │
│    │ crt.sh  │       │         │    │Wappalyzer│   │  Forms  │     │  DAST   │  │Hunt │
│    │HackerTgt│       │         │    │         │    │         │     │  CVEs   │  │     │
│    │ Knockpy │       │         │    │         │    │         │     │         │  │     │
│    └─────────┘       └─────────┘    └─────────┘    └─────────┘     └─────────┘  └─────┘
│                                                                                        │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

### Current Modules Status

| Phase | Module | Tool(s) | Status |
|-------|--------|---------|--------|
| Subdomain Discovery | domain_discovery | crt.sh, HackerTarget, Knockpy | ✅ Complete |
| DNS Resolution | domain_discovery | All record types | ✅ Complete |
| Port Scanning | port_scan | Naabu | ✅ Complete |
| HTTP Probing | http_probe | httpx + Wappalyzer | ✅ Complete |
| Active Crawling | resource_enum | Katana | ✅ Complete |
| Form Extraction | resource_enum | Custom HTML parser | ✅ Complete |
| GET Param Discovery | resource_enum | Katana (active crawl) | ⚠️ Partial |
| GET Vuln Testing | vuln_scan | Nuclei DAST | ✅ Complete |
| Secret Hunting | github | Custom GitHub scanner | ✅ Complete |

---

## GAP ANALYSIS: What's Missing

### Legend
- ✅ **Complete** - Fully implemented
- ⚠️ **Partial** - Basic implementation, needs enhancement
- ❌ **Missing** - Not implemented

---

## 1. ENDPOINT DISCOVERY GAPS

| Capability | Current Status | Missing Tool(s) | Impact |
|------------|----------------|-----------------|--------|
| Passive URL Discovery | ❌ Missing | GAU, Waymore, ParamSpider | High - Misses historical/archived endpoints |
| JS Endpoint Extraction | ⚠️ Partial (Katana) | LinkFinder, JSluice, SecretFinder | High - APIs hidden in JS not fully extracted |
| API Route Discovery | ❌ Missing | Kiterunner | Critical - REST/GraphQL APIs not discovered |
| Hidden Parameter Discovery | ❌ Missing | Arjun, x8, Param Miner | Critical - Hidden params = hidden vulns |
| Deep Recursive Crawling | ⚠️ Partial | Hakrawler, GoSpider | Medium - May miss deep nested content |

---

## 2. VULNERABILITY TESTING GAPS

| Capability | Current Status | Missing Tool(s) | Impact |
|------------|----------------|-----------------|--------|
| POST Form Fuzzing | ❌ Missing | ffuf, Burp Intruder | Critical - POST vulns not tested |
| JSON API Fuzzing | ❌ Missing | ffuf, Postman | Critical - API vulns not tested |
| XSS Deep Testing | ❌ Missing | Dalfox, XSStrike | High - XSS often missed by Nuclei |
| SQL Injection Deep | ⚠️ Partial (Nuclei) | SQLMap, Ghauri | High - Complex SQLi missed |
| NoSQL Injection | ❌ Missing | NoSQLMap | Medium - MongoDB/CouchDB vulns |
| Command Injection | ⚠️ Partial (Nuclei) | Commix | Medium - Complex OS injection |
| SSRF Testing | ⚠️ Partial (Nuclei) | SSRFmap | Medium - Complex SSRF chains |
| SSTI Testing | ⚠️ Partial (Nuclei) | tplmap | Low - Template injection |

---

## 3. EXPOSED ASSET DISCOVERY GAPS

| Capability | Current Status | Missing Tool(s) | Impact |
|------------|----------------|-----------------|--------|
| Directory Bruteforcing | ❌ Missing | Feroxbuster, Gobuster, Dirsearch | Critical - Hidden dirs not found |
| Backup File Discovery | ❌ Missing | Feroxbuster + wordlists | High - .bak, .old, .zip files |
| Config File Exposure | ❌ Missing | Custom nuclei templates | High - .env, config.php, etc. |
| Cloud Bucket Discovery | ❌ Missing | S3Scanner, CloudBrute | High - Exposed S3/Azure/GCP |
| Git Repository Exposure | ⚠️ Partial | GitTools, git-dumper | Medium - .git folder exposure |
| Source Code Leaks | ❌ Missing | TruffleHog, Gitleaks | High - Secrets in source |

---

## 4. USER & IDENTITY ENUMERATION GAPS

| Capability | Current Status | Missing Tool(s) | Impact |
|------------|----------------|-----------------|--------|
| Username Enumeration | ❌ Missing | linkedin2username, NameSpi | Medium - Social engineering |
| Email Harvesting | ❌ Missing | theHarvester, Hunter.io | Medium - Phishing targets |
| AD User Enumeration | ❌ Missing | Kerbrute | Medium - Internal network |
| Web User Enumeration | ❌ Missing | Custom scripts | Low - Login page enum |

---

## DETAILED TOOL RECOMMENDATIONS

### PRIORITY 1: PASSIVE URL DISCOVERY (Critical)

#### 1.1 GAU (GetAllUrls)
**Purpose:** Fetch historical URLs from archives without touching the target

**Data Sources:**
- Wayback Machine (web.archive.org)
- Common Crawl (index.commoncrawl.org)
- AlienVault OTX (otx.alienvault.com)
- URLScan (urlscan.io)

**Why Critical:**
- Finds old/deleted endpoints still accessible
- Discovers debug endpoints, admin panels, backup files
- Zero interaction with target during discovery
- Often finds 500+ URLs not visible in current site

**Docker Image:** `lc/gau` or install via Go

**Sample Output:**
```
http://example.com/admin/login.php
http://example.com/api/v1/users
http://example.com/backup/db_dump.sql
http://example.com/debug/phpinfo.php
http://example.com/old/config.txt
```

**Integration Point:** After `domain_discovery`, before `resource_enum`

**Configuration Parameters:**
```python
# GAU Configuration
GAU_PROVIDERS = ["wayback", "commoncrawl", "otx", "urlscan"]
GAU_BLACKLIST = ["png", "jpg", "gif", "svg", "css", "woff", "ico"]
GAU_THREADS = 5
GAU_TIMEOUT = 60
GAU_FETCH_SUBS = True  # Include subdomains
GAU_FROM_DATE = ""     # Filter by date (e.g., "202301")
GAU_TO_DATE = ""
```

**Reference:** [GitHub - lc/gau](https://github.com/lc/gau)

---

#### 1.2 Waymore
**Purpose:** Enhanced archive discovery with response downloading

**Why Better than GAU:**
- Downloads actual archived responses (not just URLs)
- Can extract additional links from archived HTML/JS
- Supports more data sources (VirusTotal, IntelligenceX)
- Finds developer comments, embedded secrets

**Docker Image:** Custom or pip install

**Configuration Parameters:**
```python
# Waymore Configuration
WAYMORE_MODE = "U"  # U=URLs only, R=Responses, B=Both
WAYMORE_PROVIDERS = ["wayback", "commoncrawl", "alienvault", "urlscan", "virustotal"]
WAYMORE_FILTER_CODES = ["200", "301", "302", "403"]
WAYMORE_LIMIT = 5000
WAYMORE_TIMEOUT = 120
```

**Reference:** [GitHub - xnl-h4ck3r/waymore](https://github.com/xnl-h4ck3r/waymore)

---

#### 1.3 ParamSpider
**Purpose:** Mine URLs with parameters from web archives

**Why Important:**
- Focuses specifically on parameter-containing URLs
- Perfect for fuzzing preparation
- Filters out static assets automatically
- Outputs in format ready for vulnerability testing

**Configuration Parameters:**
```python
# ParamSpider Configuration
PARAMSPIDER_LEVEL = "high"  # low, medium, high (nested params)
PARAMSPIDER_EXCLUDE = ["jpg", "png", "gif", "css", "js", "svg"]
PARAMSPIDER_OUTPUT_FORMAT = "txt"  # txt, json
PARAMSPIDER_PLACEHOLDER = "FUZZ"  # Replace param values
```

**Reference:** [GitHub - devanshbatham/ParamSpider](https://github.com/devanshbatham/ParamSpider)

---

### PRIORITY 2: JAVASCRIPT ANALYSIS (Critical)

#### 2.1 LinkFinder
**Purpose:** Extract endpoints from JavaScript files

**What It Finds:**
- API endpoints (`/api/v1/users`, `/graphql`)
- Internal paths (`/admin`, `/debug`, `/internal`)
- Third-party integrations
- Hardcoded URLs

**How It Works:**
- Uses jsbeautifier + regex patterns
- Parses both inline and external JS
- Outputs in HTML or plaintext

**Docker Image:** `ghcr.io/gwen001/linkfinder`

**Configuration Parameters:**
```python
# LinkFinder Configuration
LINKFINDER_OUTPUT = "cli"  # cli, html
LINKFINDER_REGEX = None    # Custom regex pattern
LINKFINDER_DOMAIN = True   # Filter by domain
LINKFINDER_COOKIES = ""    # Authentication cookies
```

**Reference:** [GitHub - GerbenJavado/LinkFinder](https://github.com/GerbenJavado/LinkFinder)

---

#### 2.2 JSluice
**Purpose:** Advanced JS analysis with AST parsing

**Why Better than LinkFinder:**
- Uses go-tree-sitter (AST parsing, not just regex)
- Understands string concatenation
- Extracts secrets (API keys, tokens)
- More accurate path reconstruction

**What It Extracts:**
- URLs and paths
- Secrets (API keys, tokens, passwords)
- Custom patterns via matchers

**Docker Image:** Custom build from source

**Configuration Parameters:**
```python
# JSluice Configuration
JSLUICE_MODE = "urls"  # urls, secrets, both
JSLUICE_PATTERNS = []  # Custom secret patterns
JSLUICE_RESOLVE_PATHS = True
```

**Reference:** [GitHub - BishopFox/jsluice](https://github.com/BishopFox/jsluice)

---

#### 2.3 SecretFinder
**Purpose:** Find secrets in JavaScript files

**What It Finds:**
- API keys (Google, AWS, Azure, etc.)
- OAuth tokens
- JWT tokens
- Private keys
- Database connection strings

**Reference:** [GitHub - m4ll0k/SecretFinder](https://github.com/m4ll0k/SecretFinder)

---

### PRIORITY 3: API DISCOVERY (Critical)

#### 3.1 Kiterunner
**Purpose:** Bruteforce API routes using OpenAPI/Swagger datasets

**Why Critical:**
- Traditional wordlists miss API routes
- Uses 40,000+ Swagger specifications
- Sends correct HTTP methods, headers, parameters
- Handles virtual routing at different depths

**Key Features:**
- Depth-based scanning (handles path-based routing)
- Request replay for verification
- Swagger-aware bruteforcing
- Extremely fast

**Docker Image:** `assetnote/kiterunner`

**Wordlists:**
- `routes-large.kite` - Comprehensive API routes
- `routes-small.kite` - Quick scan
- Custom wordlists from Assetnote

**Configuration Parameters:**
```python
# Kiterunner Configuration
KITERUNNER_WORDLIST = "routes-large.kite"  # or routes-small.kite
KITERUNNER_DEPTH = 1        # Virtual routing depth
KITERUNNER_THREADS = 50     # -x flag
KITERUNNER_CONNECTIONS = 100  # -j flag
KITERUNNER_DELAY = 0        # Request delay (ms)
KITERUNNER_TIMEOUT = 10     # Request timeout
KITERUNNER_HEADERS = {}     # Custom headers
KITERUNNER_IGNORE_CODES = [404, 400]
```

**Reference:** [GitHub - assetnote/kiterunner](https://github.com/assetnote/kiterunner)

---

### PRIORITY 4: HIDDEN PARAMETER DISCOVERY (Critical)

#### 4.1 Arjun
**Purpose:** Discover hidden HTTP parameters

**Why Critical:**
- Parameters not in forms/URLs often vulnerable
- Uses 25,890 parameter names
- Only 50-60 requests to test entire wordlist
- Supports GET, POST, XML, JSON

**What It Finds:**
- Debug parameters (`?debug=1`, `?admin=true`)
- Hidden functionality (`?test=1`, `?internal=1`)
- Version params (`?v=2`, `?api_version=old`)

**Docker Image:** `s0md3v/arjun`

**Configuration Parameters:**
```python
# Arjun Configuration
ARJUN_METHODS = ["GET", "POST", "JSON"]
ARJUN_WORDLIST = "default"  # or custom path
ARJUN_THREADS = 5
ARJUN_DELAY = 0
ARJUN_TIMEOUT = 15
ARJUN_HEADERS = {}
ARJUN_STABLE = True  # Stability check
```

**Reference:** [GitHub - s0md3v/Arjun](https://github.com/s0md3v/Arjun)

---

#### 4.2 x8
**Purpose:** Fast, Rust-powered parameter discovery

**Why Consider:**
- Faster than Arjun (Rust vs Python)
- Better handling of edge cases
- More accurate reflection detection
- Extensive configuration options

**Reference:** [GitHub - Sh1Yo/x8](https://github.com/Sh1Yo/x8)

---

### PRIORITY 5: DIRECTORY ENUMERATION (High)

#### 5.1 Feroxbuster
**Purpose:** Fast recursive directory bruteforcing

**Why Best Choice:**
- Written in Rust (extremely fast)
- Recursive by default
- Link extraction during crawl
- Burp Suite integration
- Smart filtering

**Docker Image:** `epi052/feroxbuster`

**Configuration Parameters:**
```python
# Feroxbuster Configuration
FEROXBUSTER_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
FEROXBUSTER_EXTENSIONS = ["php", "asp", "aspx", "jsp", "html", "js", "json", "txt", "bak", "old"]
FEROXBUSTER_THREADS = 50
FEROXBUSTER_DEPTH = 4
FEROXBUSTER_TIMEOUT = 10
FEROXBUSTER_STATUS_CODES = "200,204,301,302,307,401,403,405"
FEROXBUSTER_FILTER_SIZE = []  # Filter by response size
FEROXBUSTER_FILTER_WORDS = []  # Filter by word count
FEROXBUSTER_AUTO_CALIBRATION = True
```

**Reference:** [GitHub - epi052/feroxbuster](https://github.com/epi052/feroxbuster)

---

#### 5.2 Gobuster
**Purpose:** Multi-mode directory/DNS/vhost bruteforcing

**Modes:**
- `dir` - Directory bruteforcing
- `dns` - DNS subdomain bruteforcing
- `vhost` - Virtual host bruteforcing
- `s3` - AWS S3 bucket enumeration
- `gcs` - Google Cloud Storage
- `fuzz` - Fuzzing mode

**Docker Image:** `ghcr.io/oj/gobuster`

**Configuration Parameters:**
```python
# Gobuster Configuration
GOBUSTER_MODE = "dir"  # dir, dns, vhost, s3, gcs, fuzz
GOBUSTER_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"
GOBUSTER_THREADS = 50
GOBUSTER_TIMEOUT = 10
GOBUSTER_EXTENSIONS = "php,html,txt,bak"
GOBUSTER_STATUS_CODES = "200,204,301,302,307,401,403"
GOBUSTER_FOLLOW_REDIRECT = False
```

**Reference:** [GitHub - OJ/gobuster](https://github.com/OJ/gobuster)

---

### PRIORITY 6: VULNERABILITY FUZZING (Critical)

#### 6.1 ffuf (Fuzz Faster U Fool)
**Purpose:** Fast web fuzzer for GET/POST/JSON fuzzing

**Why Critical:**
- Tests POST forms (RedAmon's main gap)
- JSON API fuzzing
- Multiple fuzzing positions
- Advanced filtering
- Integration with other tools

**Use Cases:**
- POST parameter fuzzing
- JSON body fuzzing
- Header fuzzing
- Mutation-based fuzzing

**Docker Image:** `ffuf/ffuf`

**Configuration Parameters:**
```python
# ffuf Configuration
FFUF_WORDLIST = "/usr/share/seclists/Fuzzing/special-chars.txt"
FFUF_THREADS = 40
FFUF_RATE = 0  # Requests per second (0 = unlimited)
FFUF_TIMEOUT = 10
FFUF_MATCH_CODES = "200,204,301,302,307,401,403,405,500"
FFUF_FILTER_CODES = "404"
FFUF_FILTER_SIZE = ""  # Filter by size
FFUF_FILTER_WORDS = ""  # Filter by word count
FFUF_FILTER_LINES = ""  # Filter by line count
FFUF_RECURSION = False
FFUF_RECURSION_DEPTH = 0
```

**Example Usage:**
```bash
# POST form fuzzing
ffuf -X POST -u https://target.com/login -d "username=FUZZ&password=test" -w usernames.txt

# JSON API fuzzing
ffuf -X POST -u https://target.com/api -H "Content-Type: application/json" -d '{"user":"FUZZ"}' -w payloads.txt

# Header fuzzing
ffuf -u https://target.com -H "X-Custom: FUZZ" -w headers.txt
```

**Reference:** [GitHub - ffuf/ffuf](https://github.com/ffuf/ffuf)

---

#### 6.2 Dalfox
**Purpose:** Advanced XSS scanner and parameter analysis

**Why Better than Nuclei for XSS:**
- Dedicated XSS detection engine
- DOM XSS, Reflected XSS, Stored XSS
- WAF bypass payloads
- Blind XSS support (with xsshunter)
- Parameter analysis

**Docker Image:** `hahwul/dalfox`

**Configuration Parameters:**
```python
# Dalfox Configuration
DALFOX_MODE = "url"  # url, pipe, file
DALFOX_BLIND = ""    # Blind XSS callback URL
DALFOX_WAF = False   # WAF evasion mode
DALFOX_FOLLOW_REDIRECT = True
DALFOX_TIMEOUT = 10
DALFOX_DELAY = 0
DALFOX_WORKERS = 10
DALFOX_OUTPUT_FORMAT = "json"
```

**Reference:** [GitHub - hahwul/dalfox](https://github.com/hahwul/dalfox)

---

#### 6.3 SQLMap
**Purpose:** Automated SQL injection detection and exploitation

**Why Needed:**
- Nuclei finds basic SQLi
- SQLMap handles complex cases
- Full exploitation capability
- Multiple database support
- WAF bypass techniques

**Docker Image:** Custom or system install

**Configuration Parameters:**
```python
# SQLMap Configuration
SQLMAP_LEVEL = 3      # 1-5 (test thoroughness)
SQLMAP_RISK = 2       # 1-3 (risk of tests)
SQLMAP_THREADS = 5
SQLMAP_TIMEOUT = 30
SQLMAP_RETRIES = 3
SQLMAP_DBMS = ""      # Target DBMS (mysql, postgresql, etc.)
SQLMAP_TECHNIQUE = "BEUSTQ"  # Boolean, Error, Union, Stacked, Time, Query
SQLMAP_TAMPER = []    # Tamper scripts for WAF bypass
```

**Reference:** [GitHub - sqlmapproject/sqlmap](https://github.com/sqlmapproject/sqlmap)

---

#### 6.4 XSStrike
**Purpose:** Most advanced XSS scanner

**Features:**
- Multiple parsers for context analysis
- Intelligent payload generation
- DOM XSS scanning
- WAF detection and bypass
- Fuzzing engine

**Reference:** [GitHub - s0md3v/XSStrike](https://github.com/s0md3v/XSStrike)

---

#### 6.5 Commix
**Purpose:** OS command injection exploitation

**Features:**
- Automated detection and exploitation
- Multiple injection techniques
- Shell access
- File operations
- Cross-platform

**Reference:** [GitHub - commixproject/commix](https://github.com/commixproject/commix)

---

#### 6.6 NoSQLMap
**Purpose:** NoSQL database injection testing

**Supported Databases:**
- MongoDB
- CouchDB
- Redis (planned)
- Cassandra (planned)

**Configuration Parameters:**
```python
# NoSQLMap Configuration
NOSQLMAP_PLATFORM = "MongoDB"
NOSQLMAP_TECHNIQUE = "boolean"  # boolean, error, time
```

**Reference:** [GitHub - codingo/NoSQLMap](https://github.com/codingo/NoSQLMap)

---

### PRIORITY 7: CLOUD & SECRET SCANNING (High)

#### 7.1 S3Scanner
**Purpose:** Scan for misconfigured S3 buckets

**Supported Providers:**
- AWS S3
- Google Cloud Storage
- DigitalOcean Spaces
- Custom S3-compatible

**Configuration Parameters:**
```python
# S3Scanner Configuration
S3SCANNER_PROVIDERS = ["aws", "gcp", "digitalocean"]
S3SCANNER_THREADS = 5
S3SCANNER_ENUMERATE = True  # List bucket contents
S3SCANNER_OUTPUT = "json"
```

**Reference:** [GitHub - sa7mon/S3Scanner](https://github.com/sa7mon/S3Scanner)

---

#### 7.2 TruffleHog
**Purpose:** Find and verify leaked credentials

**Features:**
- 800+ secret types classified
- Live credential verification
- Git history scanning
- Filesystem scanning
- S3 bucket scanning

**Configuration Parameters:**
```python
# TruffleHog Configuration
TRUFFLEHOG_SCANNERS = ["git", "filesystem", "s3"]
TRUFFLEHOG_VERIFY = True  # Verify credentials are live
TRUFFLEHOG_ONLY_VERIFIED = False
TRUFFLEHOG_JSON = True
```

**Reference:** [GitHub - trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog)

---

#### 7.3 Gitleaks
**Purpose:** Fast secret detection in git repos

**Why Complementary to TruffleHog:**
- Faster scanning
- Different detection patterns
- Better for CI/CD integration

**Configuration Parameters:**
```python
# Gitleaks Configuration
GITLEAKS_CONFIG = "default"  # or custom config path
GITLEAKS_VERBOSE = True
GITLEAKS_REDACT = False
GITLEAKS_FORMAT = "json"
```

**Reference:** [GitHub - gitleaks/gitleaks](https://github.com/gitleaks/gitleaks)

---

### PRIORITY 8: WEB CRAWLING ENHANCEMENT (Medium)

#### 8.1 Hakrawler
**Purpose:** Fast endpoint and asset discovery

**Features:**
- Spidering with Wayback integration
- robots.txt and sitemap.xml parsing
- Subdomain collection
- JavaScript URL extraction

**Reference:** [GitHub - hakluke/hakrawler](https://github.com/hakluke/hakrawler)

---

#### 8.2 GoSpider
**Purpose:** Fast web spider with S3 bucket detection

**Features:**
- High speed (Go-based)
- Wayback integration
- S3 bucket detection
- Cookie and header support
- Output filtering

**Reference:** [GitHub - jaeles-project/gospider](https://github.com/jaeles-project/gospider)

---

### PRIORITY 9: USER ENUMERATION (Medium)

#### 9.1 linkedin2username
**Purpose:** Generate username lists from LinkedIn

**Use Case:**
- Social engineering preparation
- Password spray wordlists
- Email harvesting

**Reference:** [GitHub - initstring/linkedin2username](https://github.com/initstring/linkedin2username)

---

#### 9.2 theHarvester
**Purpose:** Email and subdomain harvesting

**Data Sources:**
- Search engines
- PGP key servers
- SHODAN
- DNS brute-force

**Reference:** [GitHub - laramies/theHarvester](https://github.com/laramies/theHarvester)

---

#### 9.3 Kerbrute
**Purpose:** Active Directory user enumeration

**Features:**
- Kerberos pre-auth enumeration
- Password spraying
- Extremely fast
- No account lockouts

**Reference:** [GitHub - ropnop/kerbrute](https://github.com/ropnop/kerbrute)

---

## ENHANCED PIPELINE ARCHITECTURE

```
┌────────────────────────────────────────────────────────────────────────────────────────────────┐
│                              ENHANCED REDAMON PIPELINE                                          │
├────────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────────────────────┐   │
│  │                            PHASE 1: RECONNAISSANCE                                       │   │
│  ├─────────────────────────────────────────────────────────────────────────────────────────┤   │
│  │                                                                                         │   │
│  │   domain_discovery ──► port_scan ──► http_probe                                        │   │
│  │        │                    │              │                                            │   │
│  │   [WHOIS, crt.sh,     [Naabu]       [httpx, Wappalyzer]                                │   │
│  │    HackerTarget,                                                                        │   │
│  │    Knockpy]                                                                             │   │
│  │                                                                                         │   │
│  └─────────────────────────────────────────────────────────────────────────────────────────┘   │
│                                           │                                                    │
│                                           ▼                                                    │
│  ┌─────────────────────────────────────────────────────────────────────────────────────────┐   │
│  │                     PHASE 2: PASSIVE ENDPOINT DISCOVERY (NEW)                           │   │
│  ├─────────────────────────────────────────────────────────────────────────────────────────┤   │
│  │                                                                                         │   │
│  │   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐                │   │
│  │   │     GAU     │   │   Waymore   │   │ ParamSpider │   │  theHarvester│               │   │
│  │   │  (Archives) │   │ (Archives+) │   │  (Params)   │   │   (Emails)   │               │   │
│  │   └──────┬──────┘   └──────┬──────┘   └──────┬──────┘   └──────┬──────┘               │   │
│  │          │                 │                 │                 │                       │   │
│  │          └─────────────────┴─────────────────┴─────────────────┘                       │   │
│  │                                    │                                                    │   │
│  │                            [Merge & Dedupe]                                            │   │
│  │                                                                                         │   │
│  └─────────────────────────────────────────────────────────────────────────────────────────┘   │
│                                           │                                                    │
│                                           ▼                                                    │
│  ┌─────────────────────────────────────────────────────────────────────────────────────────┐   │
│  │                      PHASE 3: ACTIVE ENDPOINT DISCOVERY                                 │   │
│  ├─────────────────────────────────────────────────────────────────────────────────────────┤   │
│  │                                                                                         │   │
│  │   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐                │   │
│  │   │   Katana    │   │  Hakrawler  │   │   GoSpider  │   │ Feroxbuster │               │   │
│  │   │  (Crawl)    │   │  (Spider)   │   │  (Spider)   │   │   (Dirs)    │               │   │
│  │   └──────┬──────┘   └──────┬──────┘   └──────┬──────┘   └──────┬──────┘               │   │
│  │          │                 │                 │                 │                       │   │
│  │          └─────────────────┴─────────────────┴─────────────────┘                       │   │
│  │                                    │                                                    │   │
│  │                            [Merge & Dedupe]                                            │   │
│  │                                                                                         │   │
│  └─────────────────────────────────────────────────────────────────────────────────────────┘   │
│                                           │                                                    │
│                                           ▼                                                    │
│  ┌─────────────────────────────────────────────────────────────────────────────────────────┐   │
│  │                      PHASE 4: JS & API ANALYSIS (NEW)                                   │   │
│  ├─────────────────────────────────────────────────────────────────────────────────────────┤   │
│  │                                                                                         │   │
│  │   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐                │   │
│  │   │ LinkFinder  │   │   JSluice   │   │SecretFinder │   │ Kiterunner  │               │   │
│  │   │ (JS paths)  │   │ (JS AST)    │   │ (JS secrets)│   │  (API brute)│               │   │
│  │   └──────┬──────┘   └──────┬──────┘   └──────┬──────┘   └──────┬──────┘               │   │
│  │          │                 │                 │                 │                       │   │
│  │          └─────────────────┴─────────────────┴─────────────────┘                       │   │
│  │                                    │                                                    │   │
│  │                            [Merge & Classify]                                          │   │
│  │                                                                                         │   │
│  └─────────────────────────────────────────────────────────────────────────────────────────┘   │
│                                           │                                                    │
│                                           ▼                                                    │
│  ┌─────────────────────────────────────────────────────────────────────────────────────────┐   │
│  │                      PHASE 5: PARAMETER DISCOVERY (NEW)                                 │   │
│  ├─────────────────────────────────────────────────────────────────────────────────────────┤   │
│  │                                                                                         │   │
│  │   ┌─────────────┐   ┌─────────────┐                                                    │   │
│  │   │    Arjun    │   │     x8      │                                                    │   │
│  │   │ (GET/POST)  │   │  (Hidden)   │                                                    │   │
│  │   └──────┬──────┘   └──────┬──────┘                                                    │   │
│  │          │                 │                                                            │   │
│  │          └─────────────────┘                                                            │   │
│  │                   │                                                                      │   │
│  │           [Parameter Database]                                                          │   │
│  │                                                                                         │   │
│  └─────────────────────────────────────────────────────────────────────────────────────────┘   │
│                                           │                                                    │
│                                           ▼                                                    │
│  ┌─────────────────────────────────────────────────────────────────────────────────────────┐   │
│  │                      PHASE 6: VULNERABILITY SCANNING                                    │   │
│  ├─────────────────────────────────────────────────────────────────────────────────────────┤   │
│  │                                                                                         │   │
│  │   ┌───────────────────────────────────────────────────────────────────────────────┐    │   │
│  │   │                    GET Parameter Testing                                       │    │   │
│  │   │                                                                                │    │   │
│  │   │   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐                  │    │   │
│  │   │   │  Nuclei  │   │  Dalfox  │   │  SQLMap  │   │  Commix  │                  │    │   │
│  │   │   │  (DAST)  │   │  (XSS)   │   │  (SQLi)  │   │ (CMDi)   │                  │    │   │
│  │   │   └──────────┘   └──────────┘   └──────────┘   └──────────┘                  │    │   │
│  │   └───────────────────────────────────────────────────────────────────────────────┘    │   │
│  │                                                                                         │   │
│  │   ┌───────────────────────────────────────────────────────────────────────────────┐    │   │
│  │   │                    POST/JSON Testing (NEW)                                     │    │   │
│  │   │                                                                                │    │   │
│  │   │   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐                  │    │   │
│  │   │   │   ffuf   │   │ XSStrike │   │ NoSQLMap │   │  Custom  │                  │    │   │
│  │   │   │ (Fuzzer) │   │  (XSS)   │   │ (NoSQL)  │   │ (JSON)   │                  │    │   │
│  │   │   └──────────┘   └──────────┘   └──────────┘   └──────────┘                  │    │   │
│  │   └───────────────────────────────────────────────────────────────────────────────┘    │   │
│  │                                                                                         │   │
│  └─────────────────────────────────────────────────────────────────────────────────────────┘   │
│                                           │                                                    │
│                                           ▼                                                    │
│  ┌─────────────────────────────────────────────────────────────────────────────────────────┐   │
│  │                      PHASE 7: ASSET & SECRET SCANNING (NEW)                             │   │
│  ├─────────────────────────────────────────────────────────────────────────────────────────┤   │
│  │                                                                                         │   │
│  │   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐                │   │
│  │   │  S3Scanner  │   │ TruffleHog  │   │  Gitleaks   │   │   GitTools  │               │   │
│  │   │   (Cloud)   │   │  (Secrets)  │   │  (Secrets)  │   │  (.git exp) │               │   │
│  │   └─────────────┘   └─────────────┘   └─────────────┘   └─────────────┘               │   │
│  │                                                                                         │   │
│  └─────────────────────────────────────────────────────────────────────────────────────────┘   │
│                                           │                                                    │
│                                           ▼                                                    │
│  ┌─────────────────────────────────────────────────────────────────────────────────────────┐   │
│  │                      PHASE 8: ENRICHMENT & REPORTING                                    │   │
│  ├─────────────────────────────────────────────────────────────────────────────────────────┤   │
│  │                                                                                         │   │
│  │   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐                                  │   │
│  │   │MITRE CWE/   │   │   Neo4j     │   │   Report    │                                  │   │
│  │   │CAPEC Enrich │   │   Graph     │   │  Generator  │                                  │   │
│  │   └─────────────┘   └─────────────┘   └─────────────┘                                  │   │
│  │                                                                                         │   │
│  └─────────────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## PROPOSED SCAN_MODULES Configuration

```python
# =============================================================================
# SCAN MODULES - Enhanced Pipeline
# =============================================================================
# Available modules (tool-agnostic names):
#
# PHASE 1: RECONNAISSANCE (Existing)
#   - "domain_discovery"  : WHOIS + Subdomain discovery + DNS
#   - "port_scan"         : Fast port scanning (Naabu)
#   - "http_probe"        : HTTP probing + technology detection
#
# PHASE 2: PASSIVE ENDPOINT DISCOVERY (NEW)
#   - "passive_urls"      : GAU + Waymore + ParamSpider
#   - "email_harvest"     : theHarvester email collection
#
# PHASE 3: ACTIVE ENDPOINT DISCOVERY (Enhanced)
#   - "resource_enum"     : Katana crawl + form parsing (existing)
#   - "dir_enum"          : Feroxbuster/Gobuster directory brute
#   - "spider"            : Hakrawler + GoSpider deep crawl
#
# PHASE 4: JS & API ANALYSIS (NEW)
#   - "js_analysis"       : LinkFinder + JSluice + SecretFinder
#   - "api_discovery"     : Kiterunner API route bruteforce
#
# PHASE 5: PARAMETER DISCOVERY (NEW)
#   - "param_discovery"   : Arjun + x8 hidden parameter finding
#
# PHASE 6: VULNERABILITY SCANNING (Enhanced)
#   - "vuln_scan"         : Nuclei DAST (existing)
#   - "xss_scan"          : Dalfox + XSStrike deep XSS
#   - "sqli_scan"         : SQLMap deep SQL injection
#   - "post_fuzz"         : ffuf POST/JSON fuzzing
#   - "injection_scan"    : Commix + NoSQLMap
#
# PHASE 7: ASSET & SECRET SCANNING (NEW)
#   - "cloud_scan"        : S3Scanner cloud bucket discovery
#   - "secret_scan"       : TruffleHog + Gitleaks
#   - "git_exposure"      : GitTools .git folder exploitation
#
# PHASE 8: ENRICHMENT (Existing)
#   - "github"            : GitHub secret hunting
#   - "mitre_enrich"      : MITRE CWE/CAPEC (automatic with vuln_scan)
#
# =============================================================================

# PRESET CONFIGURATIONS

# Minimal (fastest)
SCAN_MODULES_MINIMAL = [
    "domain_discovery", "port_scan", "http_probe", "vuln_scan"
]

# Standard (current default + passive)
SCAN_MODULES_STANDARD = [
    "domain_discovery", "port_scan", "http_probe",
    "passive_urls", "resource_enum",
    "vuln_scan"
]

# Comprehensive (full endpoint discovery)
SCAN_MODULES_COMPREHENSIVE = [
    "domain_discovery", "port_scan", "http_probe",
    "passive_urls", "resource_enum", "dir_enum",
    "js_analysis", "api_discovery", "param_discovery",
    "vuln_scan", "xss_scan", "post_fuzz"
]

# Full (everything including cloud/secrets)
SCAN_MODULES_FULL = [
    "domain_discovery", "port_scan", "http_probe",
    "passive_urls", "email_harvest", "resource_enum", "dir_enum", "spider",
    "js_analysis", "api_discovery", "param_discovery",
    "vuln_scan", "xss_scan", "sqli_scan", "post_fuzz", "injection_scan",
    "cloud_scan", "secret_scan", "git_exposure",
    "github"
]

# Active selection
SCAN_MODULES = SCAN_MODULES_COMPREHENSIVE
```

---

## IMPLEMENTATION PRIORITY

### Phase 1: Quick Wins (1-2 days each)
1. **GAU** - Passive URL discovery (highest impact, easy)
2. **Feroxbuster** - Directory enumeration (essential gap)
3. **ffuf** - POST fuzzing (critical gap)

### Phase 2: High Impact (2-3 days each)
4. **LinkFinder/JSluice** - JS endpoint extraction
5. **Arjun** - Hidden parameter discovery
6. **Dalfox** - Advanced XSS testing

### Phase 3: Comprehensive (3-5 days each)
7. **Kiterunner** - API route discovery
8. **Waymore** - Enhanced archive discovery
9. **S3Scanner** - Cloud bucket scanning
10. **TruffleHog** - Secret detection

### Phase 4: Advanced (5+ days each)
11. **SQLMap integration** - Deep SQL injection
12. **GoSpider/Hakrawler** - Enhanced crawling
13. **NoSQLMap/Commix** - Specialized injection

---

## DOCKER IMAGES SUMMARY

| Tool | Docker Image | Size |
|------|--------------|------|
| GAU | `lc/gau` | ~15MB |
| Waymore | Custom build | ~50MB |
| ParamSpider | Custom build | ~30MB |
| LinkFinder | `ghcr.io/gwen001/linkfinder` | ~100MB |
| JSluice | Custom build | ~20MB |
| Kiterunner | `assetnote/kiterunner` | ~50MB |
| Arjun | `s0md3v/arjun` | ~50MB |
| Feroxbuster | `epi052/feroxbuster` | ~20MB |
| Gobuster | `ghcr.io/oj/gobuster` | ~15MB |
| ffuf | `ffuf/ffuf` | ~15MB |
| Dalfox | `hahwul/dalfox` | ~30MB |
| S3Scanner | `sa7mon/s3scanner` | ~20MB |
| TruffleHog | `trufflesecurity/trufflehog` | ~100MB |

---

## WORDLIST REQUIREMENTS

```bash
# SecLists (comprehensive)
git clone https://github.com/danielmiessler/SecLists.git /opt/wordlists/seclists

# Assetnote Wordlists (API-focused)
wget https://wordlists-cdn.assetnote.io/data/kiterunner/routes-large.kite
wget https://wordlists-cdn.assetnote.io/data/kiterunner/routes-small.kite

# FuzzDB
git clone https://github.com/fuzzdb-project/fuzzdb.git /opt/wordlists/fuzzdb

# Key wordlists:
# - Discovery/Web-Content/directory-list-2.3-medium.txt (dirs)
# - Discovery/Web-Content/raft-medium-directories.txt (dirs)
# - Discovery/Web-Content/common.txt (quick scan)
# - Fuzzing/special-chars.txt (injection)
# - Fuzzing/XSS/ (XSS payloads)
# - Fuzzing/SQLi/ (SQL injection)
```

---

## ESTIMATED RESOURCE REQUIREMENTS

| Scan Type | Time (1 domain) | Requests | Memory |
|-----------|-----------------|----------|--------|
| Minimal | 5-10 min | ~5,000 | 1GB |
| Standard | 15-30 min | ~20,000 | 2GB |
| Comprehensive | 1-2 hours | ~100,000 | 4GB |
| Full | 3-6 hours | ~500,000+ | 8GB |

---

## REFERENCES

### Primary Tools
- [GAU](https://github.com/lc/gau) - GetAllUrls passive discovery
- [Waymore](https://github.com/xnl-h4ck3r/waymore) - Enhanced archive discovery
- [ParamSpider](https://github.com/devanshbatham/ParamSpider) - Parameter URL mining
- [LinkFinder](https://github.com/GerbenJavado/LinkFinder) - JS endpoint extraction
- [JSluice](https://github.com/BishopFox/jsluice) - JS AST analysis
- [Kiterunner](https://github.com/assetnote/kiterunner) - API discovery
- [Arjun](https://github.com/s0md3v/Arjun) - Hidden parameter discovery
- [x8](https://github.com/Sh1Yo/x8) - Fast parameter discovery
- [Feroxbuster](https://github.com/epi052/feroxbuster) - Directory bruteforcing
- [Gobuster](https://github.com/OJ/gobuster) - Multi-mode bruteforcing
- [ffuf](https://github.com/ffuf/ffuf) - Fast web fuzzer
- [Dalfox](https://github.com/hahwul/dalfox) - XSS scanner
- [XSStrike](https://github.com/s0md3v/XSStrike) - Advanced XSS scanner
- [SQLMap](https://github.com/sqlmapproject/sqlmap) - SQL injection
- [Commix](https://github.com/commixproject/commix) - Command injection
- [NoSQLMap](https://github.com/codingo/NoSQLMap) - NoSQL injection
- [S3Scanner](https://github.com/sa7mon/S3Scanner) - Cloud bucket scanner
- [TruffleHog](https://github.com/trufflesecurity/trufflehog) - Secret scanner
- [Gitleaks](https://github.com/gitleaks/gitleaks) - Git secret scanner
- [Hakrawler](https://github.com/hakluke/hakrawler) - Web crawler
- [GoSpider](https://github.com/jaeles-project/gospider) - Fast spider
- [theHarvester](https://github.com/laramies/theHarvester) - Email harvesting

### Wordlists
- [SecLists](https://github.com/danielmiessler/SecLists) - Comprehensive wordlists
- [Assetnote Wordlists](https://wordlists.assetnote.io/) - API-focused wordlists
- [FuzzDB](https://github.com/fuzzdb-project/fuzzdb) - Fuzzing payloads

---

## CONCLUSION

RedAmon currently covers ~40% of a comprehensive reconnaissance and vulnerability testing pipeline. The main gaps are:

1. **Passive URL Discovery** - Missing historical endpoint discovery
2. **API Discovery** - No dedicated API route bruteforcing
3. **POST/JSON Fuzzing** - Only GET parameters tested
4. **Hidden Parameters** - No discovery of unlisted parameters
5. **Directory Enumeration** - Basic coverage, no recursive bruteforcing
6. **Cloud Asset Discovery** - No S3/Azure/GCP bucket scanning
7. **Advanced Injection** - Only basic Nuclei templates

Implementing the tools in this roadmap will increase coverage to ~90%+ of attack surface discovery and vulnerability detection.
