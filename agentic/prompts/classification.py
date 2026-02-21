"""
RedAmon Attack Path Classification Prompt

LLM-based classification of user intent to select the appropriate attack path and phase.
Determines both the attack methodology AND the required phase (informational/exploitation).
"""


ATTACK_PATH_CLASSIFICATION_PROMPT = """You are classifying a penetration testing request to determine:
1. The required PHASE (informational vs exploitation)
2. The ATTACK PATH TYPE (for exploitation requests only)

## Phase Types

### informational
- Reconnaissance, OSINT, information gathering
- Querying the graph database for targets, vulnerabilities, services
- Scanning and enumeration without exploitation
- Example requests:
  - "What vulnerabilities exist on 10.0.0.5?"
  - "Show me all open ports on the target"
  - "What services are running?"
  - "Query the graph for CVEs"
  - "Scan the network"
  - "What technologies are used?"

### exploitation
- Active exploitation of vulnerabilities
- Brute force / credential attacks
- Any request that involves gaining unauthorized access
- Example requests:
  - "Exploit CVE-2021-41773"
  - "Brute force SSH"
  - "Try to crack the password"
  - "Pwn the target"

## Attack Path Types (ONLY for exploitation phase)

### cve_exploit
- Exploiting known CVE vulnerabilities
- Using Metasploit exploit modules (`exploit/*`)
- Keywords: CVE-XXXX-XXXX, MS17-XXX, vulnerability, exploit, RCE, remote code execution, pwn, hack
- Requires: TARGET selection, PAYLOAD selection
- Command: `exploit`
- Example requests:
  - "Exploit CVE-2021-41773 on 10.0.0.5"
  - "Use the Apache path traversal vulnerability"
  - "Attack the target using MS17-010"
  - "Test if the server is vulnerable to Log4Shell"

### brute_force_credential_guess
- Password guessing / credential attacks
- Using THC Hydra for password brute-forcing (`execute_hydra`)
- Keywords: brute force, crack password, credential attack, dictionary attack, password spray, guess password, wordlist, login attack
- Services: SSH, FTP, RDP, VNC, SMB, MySQL, MSSQL, PostgreSQL, Telnet, POP3, IMAP, HTTP login, Tomcat
- Requires: wordlists/credential files
- Tool: `execute_hydra` (NOT metasploit_console)
- Example requests:
  - "Brute force SSH on 10.0.0.5"
  - "Try to crack the MySQL password"
  - "Password spray against the FTP server"
  - "Guess credentials for the Tomcat manager"
  - "Dictionary attack on the SSH service"
  - "Try default credentials on PostgreSQL"
  - "Try to get access to SSH guessing password"

## User Request
{objective}

## Instructions
Classify the user's request:

1. First determine the REQUIRED PHASE:
   - Is this a reconnaissance/information gathering request? -> "informational"
   - Is this an active attack/exploitation request? -> "exploitation"

2. If exploitation, determine the ATTACK PATH TYPE:
   - Does the request mention a CVE or specific vulnerability? -> "cve_exploit"
   - Does the request mention password guessing, brute force, or credential attacks? -> "brute_force_credential_guess"
   - Does the request target a login service (SSH, FTP, MySQL, etc.) with credential-based attack? -> "brute_force_credential_guess"
   - Does the request mention exploit modules or payloads? -> "cve_exploit"
   - Does the request mention wordlists or dictionaries? -> "brute_force_credential_guess"
   - Default to "cve_exploit" if unclear

3. If informational, set attack_path_type to "cve_exploit" (default, won't be used)

Output valid JSON matching this schema:

```json
{{
  "required_phase": "informational" | "exploitation",
  "attack_path_type": "cve_exploit" | "brute_force_credential_guess",
  "confidence": 0.0-1.0,
  "reasoning": "Brief explanation of the classification",
  "detected_service": "ssh" | "ftp" | "mysql" | "mssql" | "postgres" | "smb" | "rdp" | "vnc" | "telnet" | "tomcat" | "http" | null
}}
```

Notes:
- `required_phase` determines if this is reconnaissance ("informational") or active attack ("exploitation")
- `attack_path_type` is only relevant when required_phase is "exploitation"
- `detected_service` should only be set for brute_force_credential_guess, null otherwise
- `confidence` should be 0.9+ if the intent is very clear, 0.6-0.8 if somewhat ambiguous
"""
