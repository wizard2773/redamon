# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.3.0] - 2026-02-19

### Added

- **Multi-Provider LLM Support** — the agent now supports **4 AI providers** (OpenAI, Anthropic, OpenRouter, AWS Bedrock) with 400+ selectable models. Models are dynamically fetched from each provider's API and cached for 1 hour. Provider is auto-detected via a prefix convention (`openrouter/`, `bedrock/`, `claude-*`, or plain OpenAI)
- **Dynamic Model Selector** — replaced the hardcoded 11-model dropdown with a searchable, provider-grouped model picker in Project Settings. Type to filter across all providers instantly; each model shows name, context window, and pricing info
- **`GET /models` API Endpoint** — new agent endpoint that fetches available models from all configured providers in parallel. Proxied through the webapp at `/api/models`
- **`model_providers.py`** — new provider discovery module with async fetchers for OpenAI, Anthropic, OpenRouter, and AWS Bedrock APIs, with in-memory caching (1h TTL)
- **Stealth Mode** — new per-project toggle that forces the entire pipeline to use only passive and low-noise techniques:
  - Recon: disables Kiterunner and banner grabbing, switches Naabu to CONNECT scan with rate limiting, throttles httpx/Katana/Nuclei, disables DAST and interactsh callbacks
  - Agent: injects stealth rules into the system prompt — only passive/stealthy methods allowed, agent must refuse if stealth is impossible
  - GVM scanning disabled in stealth mode (generates ~50K active probes per target)
- **Stealth Mode UI** — toggle in Target section of Project Settings with description of what it does
- **Kali Sandbox Tooling Expansion** — 15+ new packages installed in the Kali container: `netcat`, `socat`, `rlwrap`, `exploitdb`, `john`, `smbclient`, `sqlmap`, `jq`, `gcc`, `g++`, `make`, `perl`, `go`
- **`kali_shell` MCP Tool** — direct Kali Linux shell command execution, available in all phases
- **`execute_code` MCP Tool** — run custom Python/Bash exploit scripts on the Kali sandbox
- **`msf_restart` MCP Tool** — restart Metasploit RPC daemon when it becomes unresponsive
- **`execute_nmap` MCP Tool** — deep service analysis, OS fingerprinting, NSE scripts (consolidated from previous naabu-only setup)
- **MCP Server Consolidation** — merged curl and naabu servers into a unified `network_recon_server.py`, added dedicated `nmap_server.py`, fixed tool loading race condition
- **Failure Loop Detection** — agent detects 3+ consecutive similar failures and injects a pivot warning to break out of unproductive loops
- **Prompt Token Optimization** — lazy no-module fallback injection (saves ~1.1K tokens), compact formatting for older execution trace steps (full output only for last 5), trimmed rarely-used wordlist tables
- **Metasploit Prewarm** — pre-initializes Metasploit console on agent startup to reduce first-use latency
- **Markdown Report Export** — download the full agent conversation as a formatted Markdown file
- **Hydra Brute Force & CVE Exploit Settings** — new Project Settings sections for configuring Hydra brute force (threads, timeouts, extra checks, wordlist limits) and CVE exploit attack path parameters
- **Node.js Deserialization Guinea Pig** — new test environment for CVE-2017-5941 (node-serialize RCE)
- **Phase Tools Tooltip** — hover on phase badges to see which MCP tools are available in that phase
- **GitHub Secrets Suggestion** — new suggestion button in AI Assistant to leverage discovered GitHub secrets during exploitation

### Changed

- **Agent Orchestrator** — rewritten `_setup_llm()` with 4-way provider detection (OpenAI, Anthropic, OpenRouter via ChatOpenAI + custom base_url, Bedrock via ChatBedrockConverse with lazy import)
- **Model Display** — `formatModelDisplay()` helper cleans up prefixed model names in the AI Assistant badge and markdown export (e.g., `openrouter/meta-llama/llama-4-maverick` → `llama-4-maverick (OR)`)
- **Prompt Architecture** — tool registry extracted into dedicated `tool_registry.py`, attack path prompts (CVE exploit, brute force, post-exploitation) significantly reworked for better token efficiency and exploitation success rates
- **curl-based Exploitation** — expanded curl-based vulnerability probing and no-module fallback workflows for when Metasploit modules aren't available
- **kali_shell & execute_nuclei** — expanded to all phases (previously restricted)
- **GVM Button** — disabled in stealth mode with tooltip explaining why
- **README** — extensive updates: 4-provider documentation, AI Model Providers section, Kali sandbox tooling tables, new badges (400+ AI Models, Stealth Mode, Full Kill Chain, 30+ Security Tools, 9000+ Vuln Templates, 170K+ NVTs, 180+ Settings), version bump to v1.3.0

---

## [1.2.0] - 2026-02-13

### Added

- **GVM Vulnerability Scanning** — full end-to-end integration of Greenbone Vulnerability Management (GVM/OpenVAS) into the RedAmon pipeline:
  - Python scanner module (`gvm_scan/`) with `GVMScanner` class wrapping the GMP protocol for headless API-based scanning
  - Orchestrator endpoints (`/gvm/{id}/start`, `/gvm/{id}/status`, `/gvm/{id}/stop`, `/gvm/{id}/logs`) with SSE log streaming
  - Webapp API routes, `useGvmStatus` polling hook, `useGvmSSE` streaming hook, toolbar buttons, and log drawer on the Graph page
  - Neo4j graph integration — GVM findings stored as `Vulnerability` nodes (source="gvm") linked to IP/Subdomain via `HAS_VULNERABILITY`, with associated `CVE` nodes
  - JSON result download from the Graph page toolbar
- **GitHub Secret Hunt** — automated secret and credential detection across GitHub organizations and user repositories:
  - Python scanner module (`github_secret_hunt/`) with `GitHubSecretHunter` class supporting 40+ regex patterns for AWS, Azure, GCP, GitHub, Slack, Stripe, database connection strings, CI/CD tokens, cryptographic keys, JWT/Bearer tokens, and more
  - High-entropy string detection via Shannon entropy to catch unknown secret formats
  - Sensitive filename detection (`.env`, `.pem`, `.key`, credentials files, Kubernetes kubeconfig, Terraform tfvars, etc.)
  - Commit history scanning (configurable depth, default 100 commits) and gist scanning
  - Organization member repository enumeration with rate-limit handling and exponential backoff
  - Orchestrator endpoints (`/github-hunt/{id}/start`, `/github-hunt/{id}/status`, `/github-hunt/{id}/stop`, `/github-hunt/{id}/logs`) with SSE log streaming
  - Webapp API routes for start, status, stop, log streaming, and JSON result download
  - `useGithubHuntStatus` polling hook and `useGithubHuntSSE` streaming hook for real-time UI updates
  - Graph page toolbar integration with start/stop button, log drawer, and result download
  - JSON output with statistics (repos scanned, files scanned, commits scanned, gists scanned, secrets found, sensitive files, high-entropy findings)
- **GitHub Hunt Per-Project Settings** — GitHub scan configuration is now configurable per-project via the webapp UI:
  - New "GitHub" section in Project Settings with token, target org/user, and scan options
  - 7 configurable fields: Access Token, Target Organization, Scan Members, Scan Gists, Scan Commits, Max Commits, Output JSON
  - `github_secret_hunt/project_settings.py` mirrors the recon/GVM settings pattern (fetch from webapp API, fallback to defaults)
  - 7 new Prisma schema fields (`github_access_token`, `github_target_org`, `github_scan_members`, `github_scan_gists`, `github_scan_commits`, `github_max_commits`, `github_output_json`)
- **GVM Per-Project Settings** — GVM scan configuration is now configurable per-project via the webapp UI:
  - New "GVM Scan" tab in Project Settings (between Integrations and Agent Behaviour)
  - 5 configurable fields: Scan Profile, Scan Targets Strategy, Task Timeout, Poll Interval, Cleanup After Scan
  - `gvm_scan/project_settings.py` mirrors the recon/agentic settings pattern (fetch from webapp API, fallback to defaults)
  - Defaults served via orchestrator `/defaults` endpoint using `importlib` to avoid module name collision
  - 5 new Prisma schema fields (`gvm_scan_config`, `gvm_scan_targets`, `gvm_task_timeout`, `gvm_poll_interval`, `gvm_cleanup_after_scan`)

### Changed

- **Webapp Dockerfile** — embedded Prisma CLI in the production image; entrypoint now runs `prisma db push` automatically on startup, eliminating the separate `webapp-init` container
- **Dev Compose** — `docker-compose.dev.yml` now runs `prisma db push` before `npm run dev` to ensure schema is always in sync
- **Docker Compose** — removed `webapp-init` service and `webapp_prisma_cache` volume; webapp handles its own schema migration

### Removed

- **`webapp-init` service** — replaced by automatic migration in the webapp entrypoint (both production and dev modes)
- **`gvm_scan/params.py`** — hardcoded GVM settings replaced by per-project `project_settings.py`

---

## [1.1.0] - 2026-02-08

### Added

- **Attack Path System** — agent now supports dynamic attack path selection with two built-in paths:
  - **CVE Exploit** — automated Metasploit module search, payload configuration, and exploit execution
  - **Hydra Brute Force** — THC Hydra-based credential guessing with configurable threads, timeouts, extra checks, and wordlist retry strategies
- **Agent Guidance** — send real-time steering messages to the agent while it works, injected into the system prompt before the next reasoning step
- **Agent Stop & Resume** — stop the agent at any point and resume from the last LangGraph checkpoint with full context preserved
- **Project Creation UI** — full frontend project form with all configurable settings sections:
  - Naabu (port scanner), Httpx (HTTP prober), Katana (web crawler), GAU (passive URLs), Kiterunner (API discovery), Nuclei (vulnerability scanner), and agent behavior settings
- **Agent Settings in Frontend** — transferred agent configuration parameters from hardcoded `params.py` to PostgreSQL, editable via webapp UI
- **Metasploit Progress Streaming** — HTTP progress endpoint (port 8013) for real-time MSF command tracking with ANSI escape code cleaning
- **Metasploit Session Auto-Reset** — `msf_restart()` MCP tool for clean msfconsole state; auto-reset on first use per chat session
- **WebSocket Integration** — real-time bidirectional communication between frontend and agent orchestrator
- **Markdown Chat UI** — react-markdown with syntax highlighting for agent chat messages
- **Smart Auto-Scroll** — chat only auto-scrolls when user is at the bottom of the conversation
- **Connection Status Indicator** — color-coded WebSocket connection status (green/red) in the chat interface

### Changed

- **Unified Docker Compose** — replaced per-module `.env` files and `start.sh`/`stop.sh` scripts with a single root `docker-compose.yml` and `docker-compose.dev.yml` for full-stack orchestration
- **Settings Source of Truth** — migrated all recon and agent settings from hardcoded `params.py` to PostgreSQL via Prisma ORM, fetched at runtime via webapp API
- **Recon Pipeline Improvements** — multi-level improvements across all recon modules for reliability and accuracy
- **Orchestrator Model Selection** — fixed model selection logic in the agent orchestrator
- **Frontend Usability** — unified RedAmon primary crimson color (#d32f2f), styled message containers with ghost icons and gradient backgrounds, improved markdown heading and list spacing
- **Environment Configuration** — added root `.env.example` with all required keys; forwarded NVD_API_KEY and Neo4j credentials from recon-orchestrator to spawned containers
- **Webapp Header** — replaced Crosshair icon with custom logo.png image, bumped logo text size

### Fixed

- **Double Approval Dialog** — fixed duplicate approval confirmation with ref-based state tracking
- **Orchestrator Model Selection** — corrected model selection logic when switching between AI providers

---

## [1.0.0] - Initial Release

### Added

- Automated reconnaissance pipeline (6-phase: domain discovery, port scanning, HTTP probing, resource enumeration, vulnerability scanning, MITRE mapping)
- Neo4j graph database with 17 node types and 20+ relationship types
- MCP tool servers (Naabu, Curl, Nuclei, Metasploit)
- LangGraph-based AI agent with ReAct pattern
- Next.js webapp with graph visualization (2D/3D)
- Recon orchestrator with SSE log streaming
- GVM scanner integration (under development)
- Test environments (Apache CVE containers)
