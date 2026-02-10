"""
GVM scan - Parameters
"""

# =============================================================================
# GVM/OpenVAS Vulnerability Scanner Configuration
# =============================================================================

# Scan configuration preset:
# - "Full and fast" - Comprehensive scan, good performance (recommended)
# - "Full and fast ultimate" - Most thorough, slower
# - "Full and very deep" - Deep scan, very slow
# - "Full and very deep ultimate" - Maximum coverage, very slow
# - "Discovery" - Network discovery only, no vulnerability tests
# - "Host Discovery" - Basic host enumeration
# - "System Discovery" - System enumeration
GVM_SCAN_CONFIG = "Full and fast"

# Scan targets strategy:
# - "both" - Scan IPs and hostnames separately for thorough coverage
# - "ips_only" - Only scan IP addresses
# - "hostnames_only" - Only scan hostnames/subdomains
GVM_SCAN_TARGETS = "both"

# Maximum time to wait for a single scan task (seconds, 0 = unlimited)
# Note: "Full and fast" scans can take 1-2+ hours per target
GVM_TASK_TIMEOUT = 14400  # 4 hours (increase if needed for many targets)

# Poll interval for checking scan status (seconds)
GVM_POLL_INTERVAL = 30

# Cleanup targets and tasks after scan completion
GVM_CLEANUP_AFTER_SCAN = True

