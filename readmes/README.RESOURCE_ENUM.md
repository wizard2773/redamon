# RedAmon - Resource Enumeration Module

## Complete Technical Documentation

> **Module:** `recon/resource_enum.py`
> **Purpose:** Endpoint discovery, classification, and parameter extraction
> **Author:** RedAmon Security Suite

---

## Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Installation](#installation)
4. [Configuration Parameters](#configuration-parameters)
5. [Architecture & Flow](#architecture--flow)
6. [Output Data Structure](#output-data-structure)
7. [Endpoint Classification](#endpoint-classification)
8. [Parameter Classification](#parameter-classification)
9. [Form Parsing](#form-parsing)
10. [Usage Examples](#usage-examples)
11. [Troubleshooting](#troubleshooting)

---

## Overview

The `resource_enum.py` module provides comprehensive endpoint discovery and classification for web applications. It crawls target URLs to discover all accessible endpoints, extracts parameters, parses HTML forms, and organizes everything into a structured format ready for vulnerability scanning.

**Pipeline Position:** `http_probe -> resource_enum -> vuln_scan`

### Why Resource Enumeration?

| Feature | Without resource_enum | With resource_enum |
|---------|----------------------|-------------------|
| Endpoint Discovery | Manual or basic | **Automated crawling** |
| POST Endpoints | Missed | **Form parsing** |
| Parameter Extraction | None | **Full extraction** |
| Endpoint Classification | None | **Categorized** |
| Parameter Types | Unknown | **Inferred** |
| Vulnerability Coverage | Limited | **Comprehensive** |

### How It Works

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  http_probe     │────▶│  resource_enum   │────▶│  vuln_scan      │
│  (live URLs,    │     │                  │     │  (targeted      │
│   responses)    │     │  1. Katana crawl │     │   scanning)     │
└─────────────────┘     │  2. Form parsing │     └─────────────────┘
                        │  3. Param extract│
                        │  4. Classify     │
                        │  5. Organize     │
                        └──────────────────┘
```

---

## Features

| Feature | Description |
|---------|-------------|
| **Katana Crawling** | Deep endpoint discovery using ProjectDiscovery's Katana |
| **JavaScript Parsing** | Discovers endpoints in JavaScript files |
| **Form Extraction** | Parses HTML forms for POST endpoints |
| **Parameter Extraction** | Extracts query and body parameters |
| **Type Inference** | Infers parameter data types (integer, email, URL, etc.) |
| **Endpoint Classification** | Categorizes endpoints (auth, api, admin, file_access, etc.) |
| **Parameter Classification** | Identifies sensitive params (id, file, auth, redirect, command) |
| **Docker Execution** | Runs via Docker for consistency |
| **Tor Support** | Anonymous crawling via SOCKS proxy |
| **Incremental Output** | Saves results as crawling progresses |

---

## Installation

### Requirements

- **Docker** installed and running
- Previous pipeline steps completed (`http_probe`)

### Setup

```bash
# Make sure Docker is running
sudo systemctl start docker

# Run the scan - image will be pulled automatically
python3 recon/main.py
```

### Verify Docker is Ready

```bash
# Check Docker is running
docker info

# Optionally pre-pull the Katana image
docker pull projectdiscovery/katana:latest
```

---

## Configuration Parameters

All parameters are defined in `params.py`.

---

### 1. Core Katana Configuration

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `KATANA_DOCKER_IMAGE` | `str` | `"projectdiscovery/katana:latest"` | Docker image to use |
| `KATANA_DEPTH` | `int` | `3` | Maximum crawl depth (how many links deep to follow) |
| `KATANA_MAX_URLS` | `int` | `1000` | Maximum URLs to discover per target |
| `KATANA_RATE_LIMIT` | `int` | `150` | Requests per second |
| `KATANA_TIMEOUT` | `int` | `300` | Maximum crawl time in seconds (5 minutes) |

**Depth Tuning Guide:**

| Depth | Use Case | Coverage | Time |
|-------|----------|----------|------|
| 1 | Quick scan, homepage only | Low | Fast |
| 2 | Standard reconnaissance | Medium | Moderate |
| **3** | **Default** - balanced coverage | Good | ~5 min |
| 5+ | Deep analysis, large sites | Comprehensive | Long |

---

### 2. Crawl Behavior

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `KATANA_JS_CRAWL` | `bool` | `True` | Parse JavaScript files for endpoints |
| `KATANA_PARAMS_ONLY` | `bool` | `False` | Only keep URLs with query parameters |
| `KATANA_SCOPE` | `str` | `"rdn"` | Scope: `rdn` (root domain), `dn` (domain), `fqdn` (full) |

**Scope Options:**

| Scope | Description | Example |
|-------|-------------|---------|
| `rdn` | Root domain and all subdomains | `*.example.com` |
| `dn` | Exact domain only | `www.example.com` |
| `fqdn` | Exact FQDN only | `www.example.com` (no subdomains) |

---

### 3. Filtering

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `KATANA_EXCLUDE_PATTERNS` | `list` | See below | URL patterns to exclude |
| `KATANA_CUSTOM_HEADERS` | `list` | `[]` | Custom HTTP headers |

**Default Exclude Patterns:**

```python
KATANA_EXCLUDE_PATTERNS = [
    # Next.js / React
    "/_next/image",          # Image optimization
    "/_next/static",         # Static assets

    # WordPress
    "/wp-content/uploads",   # Media uploads
    "/wp-includes",          # Core files

    # Common static
    "/static/",              # Static directories
    "/assets/",              # Asset directories
    ".css", ".js",           # Stylesheets, scripts
    ".jpg", ".png", ".gif",  # Images
    ".woff", ".ttf",         # Fonts
]
```

---

### 4. Performance Profiles

#### Fast Mode (Quick Recon)
```python
KATANA_DEPTH = 2
KATANA_MAX_URLS = 500
KATANA_RATE_LIMIT = 200
KATANA_TIMEOUT = 120
KATANA_JS_CRAWL = False
KATANA_PARAMS_ONLY = True
```
**Expected:** ~1-2 minutes per target

#### Balanced Mode (Default)
```python
KATANA_DEPTH = 3
KATANA_MAX_URLS = 1000
KATANA_RATE_LIMIT = 150
KATANA_TIMEOUT = 300
KATANA_JS_CRAWL = True
KATANA_PARAMS_ONLY = False
```
**Expected:** ~3-5 minutes per target

#### Deep Analysis Mode
```python
KATANA_DEPTH = 5
KATANA_MAX_URLS = 5000
KATANA_RATE_LIMIT = 100
KATANA_TIMEOUT = 600
KATANA_JS_CRAWL = True
KATANA_PARAMS_ONLY = False
```
**Expected:** ~10-15 minutes per target

---

## Architecture & Flow

### Execution Flow

```
1. INITIALIZATION
   └── Check Docker availability
   └── Pull Katana image if needed
   └── Check Tor availability (if enabled)

2. TARGET EXTRACTION
   └── Get live URLs from http_probe
   └── Filter by status code (< 500)
   └── Fallback to DNS data if no http_probe

3. KATANA CRAWLING
   └── Build Docker command with options
   └── Run Katana for each target
   └── Collect discovered URLs
   └── Apply exclude patterns

4. FORM PARSING
   └── Extract HTML from http_probe responses
   └── Parse <form> elements
   └── Extract action URLs and methods
   └── Extract input fields

5. ENDPOINT ORGANIZATION
   └── Group by base URL
   └── Parse query parameters
   └── Merge form data
   └── Classify endpoints
   └── Classify parameters

6. OUTPUT GENERATION
   └── Build structured JSON
   └── Generate summary statistics
   └── Save to recon file
```

### Data Flow Diagram

```
┌──────────────────────────────────────────────────────────────────┐
│                        http_probe data                           │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐     │
│  │ live URLs      │  │ response bodies │  │ status codes   │     │
│  │ (for crawling) │  │ (for forms)     │  │ (filtering)    │     │
│  └───────┬────────┘  └───────┬────────┘  └───────┬────────┘     │
└──────────┼───────────────────┼───────────────────┼──────────────┘
           │                   │                   │
           ▼                   ▼                   │
    ┌──────────────┐    ┌──────────────┐          │
    │ Katana       │    │ Form Parser  │          │
    │ Crawler      │    │              │          │
    └──────┬───────┘    └──────┬───────┘          │
           │                   │                   │
           ▼                   ▼                   │
    ┌──────────────────────────────────────┐      │
    │          organize_endpoints()         │◄─────┘
    │  - Parse URLs                         │
    │  - Extract parameters                 │
    │  - Merge form data                    │
    │  - Classify endpoints                 │
    │  - Classify parameters                │
    └──────────────────┬───────────────────┘
                       │
                       ▼
    ┌──────────────────────────────────────┐
    │          resource_enum result         │
    │  - by_base_url (organized endpoints)  │
    │  - forms (POST endpoints)             │
    │  - discovered_urls (raw list)         │
    │  - summary (statistics)               │
    └──────────────────────────────────────┘
```

---

## Output Data Structure

### Complete JSON Schema

```json
{
  "resource_enum": {
    "scan_metadata": {
      "scan_timestamp": "2024-01-15T12:00:00.000000",
      "scan_duration_seconds": 145.5,
      "docker_image": "projectdiscovery/katana:latest",
      "crawl_depth": 3,
      "max_urls": 1000,
      "rate_limit": 150,
      "js_crawl": true,
      "params_only": false,
      "proxy_used": false,
      "target_urls_count": 5,
      "discovered_urls_count": 234
    },

    "discovered_urls": [
      "https://example.com/",
      "https://example.com/login?redirect=/dashboard",
      "https://example.com/api/v1/users?id=1",
      "https://example.com/search?q=test"
    ],

    "by_base_url": {
      "https://example.com": {
        "base_url": "https://example.com",
        "endpoints": {
          "/login": {
            "path": "/login",
            "methods": ["GET", "POST"],
            "parameters": {
              "query": [
                {
                  "name": "redirect",
                  "type": "url",
                  "sample_values": ["/dashboard", "/home"],
                  "category": "redirect_params"
                }
              ],
              "body": [
                {
                  "name": "username",
                  "type": "string",
                  "input_type": "text",
                  "required": true,
                  "category": "auth_params"
                },
                {
                  "name": "password",
                  "type": "string",
                  "input_type": "password",
                  "required": true,
                  "category": "auth_params"
                }
              ],
              "path": []
            },
            "sample_urls": ["https://example.com/login?redirect=/dashboard"],
            "urls_found": 3,
            "category": "authentication",
            "parameter_count": {
              "query": 1,
              "body": 2,
              "path": 0,
              "total": 3
            }
          },
          "/api/v1/users": {
            "path": "/api/v1/users",
            "methods": ["GET"],
            "parameters": {
              "query": [
                {
                  "name": "id",
                  "type": "integer",
                  "sample_values": ["1", "2", "100"],
                  "category": "id_params"
                }
              ],
              "body": [],
              "path": []
            },
            "sample_urls": ["https://example.com/api/v1/users?id=1"],
            "urls_found": 5,
            "category": "api",
            "parameter_count": {
              "query": 1,
              "body": 0,
              "path": 0,
              "total": 1
            }
          }
        },
        "summary": {
          "total_endpoints": 15,
          "total_parameters": 23,
          "methods": {
            "GET": 12,
            "POST": 3
          },
          "categories": {
            "api": 5,
            "authentication": 2,
            "dynamic": 4,
            "static": 3,
            "search": 1
          }
        }
      }
    },

    "forms": [
      {
        "action": "https://example.com/login",
        "method": "POST",
        "enctype": "application/x-www-form-urlencoded",
        "found_at": "https://example.com/login",
        "inputs": [
          {"name": "username", "type": "text", "value": "", "required": true},
          {"name": "password", "type": "password", "value": "", "required": true},
          {"name": "remember", "type": "checkbox", "value": "1", "required": false}
        ]
      },
      {
        "action": "https://example.com/upload",
        "method": "POST",
        "enctype": "multipart/form-data",
        "found_at": "https://example.com/dashboard",
        "inputs": [
          {"name": "file", "type": "file", "value": "", "required": true},
          {"name": "description", "type": "text", "value": "", "required": false}
        ]
      }
    ],

    "summary": {
      "total_base_urls": 3,
      "total_endpoints": 45,
      "total_parameters": 78,
      "total_forms": 5,
      "methods": {
        "GET": 38,
        "POST": 7
      },
      "categories": {
        "api": 15,
        "dynamic": 12,
        "static": 8,
        "authentication": 4,
        "search": 3,
        "admin": 2,
        "file_access": 1
      }
    }
  }
}
```

---

## Endpoint Classification

The module automatically classifies endpoints into categories based on URL patterns, HTTP methods, and parameters.

### Categories

| Category | Detection Patterns | Security Relevance |
|----------|-------------------|-------------------|
| **authentication** | `/login`, `/signup`, `/auth`, `/token`, body params with `username`/`password` | Credential stuffing, brute force |
| **admin** | `/admin`, `/dashboard`, `/panel`, `/wp-admin` | Privilege escalation |
| **api** | `/api/`, `/v1/`, `/v2/`, `/rest/`, `/graphql` | API abuse, IDOR |
| **file_access** | `/download`, `/file`, `/image`, `/attachment` | LFI, path traversal |
| **upload** | `/upload`, `/import` | Malicious file upload |
| **search** | `/search`, `/find`, `/query` | SQL injection, XSS |
| **dynamic** | `.php`, `.asp`, `.jsp`, or URLs with params | Various injection attacks |
| **static** | `.html`, `.css`, `.js`, images | Low priority |
| **other** | Everything else | Manual review |

### Classification Logic

```python
def classify_endpoint(path, methods, params):
    # Priority order:
    # 1. Check path patterns (auth, admin, api, file, search)
    # 2. Check body parameters for auth indicators
    # 3. Check file extension (static vs dynamic)
    # 4. Check for query parameters (dynamic)
    # 5. Default to "other"
```

---

## Parameter Classification

Parameters are classified to identify potentially vulnerable inputs.

### Parameter Categories

| Category | Examples | Vulnerability Risk |
|----------|----------|-------------------|
| **id_params** | `id`, `user_id`, `product_id`, `cat` | IDOR, SQL injection |
| **file_params** | `file`, `path`, `template`, `include` | LFI, RFI, path traversal |
| **search_params** | `q`, `query`, `search`, `keyword` | SQL injection, XSS |
| **auth_params** | `username`, `password`, `token`, `apikey` | Credential exposure |
| **redirect_params** | `url`, `redirect`, `next`, `callback` | Open redirect, SSRF |
| **command_params** | `cmd`, `exec`, `host`, `ip` | Command injection |
| **other** | Everything else | Context-dependent |

### Type Inference

The module infers parameter data types from names and sample values:

| Type | Detection Method | Example |
|------|------------------|---------|
| `integer` | Numeric values, names like `id`, `page` | `id=123` |
| `email` | Contains `@` and `.` | `email=user@example.com` |
| `url` | Starts with `http://` or `https://` | `redirect=https://...` |
| `path` | Contains `/`, `\`, or file extensions | `file=../etc/passwd` |
| `datetime` | Names like `date`, `time`, `timestamp` | `created_at=...` |
| `boolean` | Names like `enabled`, `active`, `is_*` | `active=true` |
| `string` | Default | Everything else |

---

## Form Parsing

The module parses HTML to extract form elements and their inputs.

### Extracted Form Information

```json
{
  "action": "https://example.com/login",
  "method": "POST",
  "enctype": "application/x-www-form-urlencoded",
  "found_at": "https://example.com/",
  "inputs": [
    {
      "name": "username",
      "type": "text",
      "value": "",
      "required": true,
      "placeholder": "Enter username"
    },
    {
      "name": "password",
      "type": "password",
      "value": "",
      "required": true
    }
  ]
}
```

### Supported Input Types

| HTML Element | Extracted Info |
|-------------|----------------|
| `<form>` | action, method, enctype |
| `<input>` | name, type, value, required, placeholder |
| `<textarea>` | name, required |
| `<select>` | name, required |
| `<button type="submit">` | name, value |

### Form Data in Endpoints

Forms are merged into the endpoint structure:
- Form `action` URL becomes the endpoint path
- Form `method` is added to endpoint methods
- Form inputs become body parameters with `input_type` field

---

## Usage Examples

### Basic Usage (via main.py)

```python
# Include "resource_enum" in SCAN_MODULES in params.py
SCAN_MODULES = ["domain_discovery", "port_scan", "http_probe", "resource_enum", "vuln_scan"]

# Run the full pipeline
python3 recon/main.py
```

### Standalone Enrichment

```python
from resource_enum import run_resource_enum
from pathlib import Path
import json

# Load existing recon data
with open("output/recon_example.com.json", "r") as f:
    recon_data = json.load(f)

# Run resource enumeration
enriched = run_resource_enum(recon_data, output_file=Path("output/recon_example.com.json"))
```

### Command Line

```bash
# Enrich an existing recon file
python3 recon/resource_enum.py output/recon_example.com.json
```

### Using Results in vuln_scan

The `vuln_scan` module automatically uses resource_enum data:

```python
# vuln_scan.py - build_target_urls()

# Priority 1: Use resource_enum endpoints (most comprehensive)
resource_enum_data = recon_data.get("resource_enum")
if resource_enum_data:
    base_urls, endpoint_urls = build_target_urls_from_resource_enum(resource_enum_data)
    # Returns both base URLs and URLs with parameters for comprehensive scanning
```

---

## Integration with Graph Database

Resource enumeration data is stored in Neo4j:

### Node Types

| Node | Properties |
|------|------------|
| **Endpoint** | path, method, category, has_parameters, query_param_count, body_param_count |
| **Parameter** | name, position (query/body), type, category, sample_values |

### Relationships

```
(BaseURL) -[:HAS_ENDPOINT]-> (Endpoint) -[:HAS_PARAMETER]-> (Parameter)
```

### Example Cypher Queries

```cypher
// Find all authentication endpoints
MATCH (e:Endpoint {category: 'authentication'})
RETURN e.path, e.method

// Find endpoints with file parameters (LFI risk)
MATCH (e:Endpoint)-[:HAS_PARAMETER]->(p:Parameter {category: 'file_params'})
RETURN e.path, p.name

// Find all POST forms
MATCH (e:Endpoint {method: 'POST', is_form: true})
RETURN e.path, e.form_found_at
```

---

## Troubleshooting

### Common Issues

#### "Docker not found"

```bash
# Install Docker
sudo apt install docker.io

# Start Docker daemon
sudo systemctl start docker
```

#### "No URLs discovered"

Possible causes:
1. JavaScript-heavy site (SPAs)
2. WAF blocking crawler
3. Rate limiting

Solutions:
```python
# Increase depth
KATANA_DEPTH = 5

# Enable JS crawling
KATANA_JS_CRAWL = True

# Reduce rate limit
KATANA_RATE_LIMIT = 50

# Use Tor for anonymous crawling
USE_TOR_FOR_RECON = True
```

#### "Too many URLs (noise)"

```python
# Enable params-only mode
KATANA_PARAMS_ONLY = True

# Add exclude patterns
KATANA_EXCLUDE_PATTERNS = [
    "/static/",
    "/assets/",
    "/wp-content/",
    ".css", ".js", ".jpg", ".png"
]

# Reduce max URLs
KATANA_MAX_URLS = 500
```

#### "Crawl taking too long"

```python
# Reduce depth
KATANA_DEPTH = 2

# Reduce timeout
KATANA_TIMEOUT = 120

# Increase rate limit
KATANA_RATE_LIMIT = 200

# Disable JS crawling
KATANA_JS_CRAWL = False
```

### Debug Mode

Run Katana manually via Docker:

```bash
docker run --rm \
  projectdiscovery/katana:latest \
  -u https://example.com \
  -d 2 \
  -jc \
  -silent
```

---

## Security Considerations

| Risk | Mitigation |
|------|------------|
| Rate limiting/bans | Reduce `KATANA_RATE_LIMIT` |
| WAF blocking | Use custom User-Agent, reduce rate |
| Detection | Use Tor proxy |
| Legal issues | Only scan authorized targets |

### Safe Defaults

```python
KATANA_RATE_LIMIT = 50
KATANA_DEPTH = 2
KATANA_TIMEOUT = 120
KATANA_CUSTOM_HEADERS = [
    "User-Agent: Mozilla/5.0 (compatible; SecurityScanner/1.0)"
]
```

---

## Dependencies

| Package | Purpose |
|---------|---------|
| Docker | Container runtime for Katana |
| `projectdiscovery/katana:latest` | Katana Docker image (auto-pulled) |
| Python 3.8+ | Script runtime |
| `html.parser` | Built-in HTML form parsing |

---

## References

- [Katana Documentation](https://github.com/projectdiscovery/katana)
- [Katana Docker Hub](https://hub.docker.com/r/projectdiscovery/katana)
- [OWASP Testing Guide - Information Gathering](https://owasp.org/www-project-web-security-testing-guide/)
- [ProjectDiscovery Blog](https://blog.projectdiscovery.io/)

---

*Documentation generated for RedAmon v1.0 - Resource Enumeration Module*
