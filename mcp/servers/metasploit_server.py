"""
Metasploit MCP Server - Stateful Exploitation Framework

Exposes Metasploit Framework as MCP tools with PERSISTENT session management.
Uses a persistent msfconsole process that maintains state between calls.

Architecture:
    - Single persistent msfconsole process per server instance
    - Module context persists between calls
    - Meterpreter/shell sessions persist until explicitly closed
    - Timing-based output detection (universal, no regex parsing)

Tools:
    - msf_execute: Execute any msfconsole command (stateful)
    - msf_sessions_list: List all active sessions
    - msf_session_run: Run command on specific session
    - msf_session_close: Close a session
    - metasploit_console: Legacy alias for msf_execute
"""

from fastmcp import FastMCP
import subprocess
import threading
import queue
import time
import os
import re
import atexit
from typing import Optional, Set, Dict

# Server configuration
SERVER_NAME = "metasploit"
SERVER_HOST = os.getenv("MCP_HOST", "0.0.0.0")
SERVER_PORT = int(os.getenv("METASPLOIT_PORT", "8003"))
DEBUG = os.getenv("MSF_DEBUG", "false").lower() == "true"

mcp = FastMCP(SERVER_NAME)


class PersistentMsfConsole:
    """
    Manages a persistent msfconsole process with bidirectional I/O.

    Uses timing-based output detection - waits for output to settle
    rather than parsing specific prompts. This is universal and works
    with any msfconsole output format.
    """

    def __init__(self):
        self.process: Optional[subprocess.Popen] = None
        self.output_queue: queue.Queue = queue.Queue()
        self.reader_thread: Optional[threading.Thread] = None
        self.lock = threading.Lock()
        self.session_ids: Set[int] = set()  # Simple set of active session IDs
        self._initialized = False

    def start(self) -> bool:
        """Start the persistent msfconsole process."""
        if self.process and self.process.poll() is None:
            return True  # Already running

        try:
            print("[MSF] Starting msfconsole process...")
            self.process = subprocess.Popen(
                ["msfconsole", "-q", "-x", ""],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            print(f"[MSF] Process started with PID: {self.process.pid}")

            # Start background thread to read output
            self.reader_thread = threading.Thread(
                target=self._read_output,
                daemon=True
            )
            self.reader_thread.start()

            # Wait for msfconsole to be ready (can take 60-120s on first start)
            self._wait_for_output(timeout=120, quiet_period=5.0)
            self._initialized = True
            print(f"[MSF] Persistent msfconsole ready (PID: {self.process.pid})")
            return True

        except Exception as e:
            print(f"[MSF] Failed to start msfconsole: {e}")
            return False

    def _read_output(self):
        """Background thread to continuously read msfconsole output."""
        if DEBUG:
            print("[MSF] Reader thread started")
        try:
            while self.process and self.process.poll() is None:
                line = self.process.stdout.readline()
                if line:
                    self.output_queue.put(line)
                    if DEBUG:
                        print(f"[MSF] OUTPUT: {line.rstrip()[:200]}")
                    self._detect_session_events(line)
        except Exception as e:
            print(f"[MSF] Reader thread error: {e}")
        if DEBUG:
            print("[MSF] Reader thread exited")

    def _detect_session_events(self, line: str):
        """
        Simple session event detection - just tracks session IDs.
        Agent gets full session details from 'sessions -l' output.
        """
        line_lower = line.lower()

        # Detect "session X opened"
        if 'session' in line_lower and 'opened' in line_lower:
            # Extract session ID with simple string parsing
            try:
                idx = line_lower.index('session')
                # Look for number after "session"
                rest = line_lower[idx + 7:].strip()
                parts = rest.split()
                if parts and parts[0].isdigit():
                    session_id = int(parts[0])
                    self.session_ids.add(session_id)
                    print(f"[MSF] Session {session_id} opened")
            except (ValueError, IndexError):
                pass

        # Detect "session X closed"
        elif 'session' in line_lower and 'closed' in line_lower:
            try:
                idx = line_lower.index('session')
                rest = line_lower[idx + 7:].strip()
                parts = rest.split()
                if parts and parts[0].isdigit():
                    session_id = int(parts[0])
                    self.session_ids.discard(session_id)
                    print(f"[MSF] Session {session_id} closed")
            except (ValueError, IndexError):
                pass

    def _wait_for_output(self, timeout: float, quiet_period: float) -> str:
        """
        Wait for msfconsole output using timing-based detection.

        Universal approach - waits until no new output arrives for
        'quiet_period' seconds, or until timeout is reached.
        """
        output_lines = []
        end_time = time.time() + timeout
        start_time = time.time()
        last_output_time = time.time()

        # Minimum wait time before returning empty (give slow commands time to start)
        min_wait = min(3.0, timeout / 2)

        while time.time() < end_time:
            try:
                line = self.output_queue.get(timeout=0.1)
                output_lines.append(line.rstrip())
                last_output_time = time.time()

            except queue.Empty:
                elapsed = time.time() - start_time
                time_since_last = time.time() - last_output_time

                # If we have output and it's been quiet, we're done
                if output_lines and time_since_last >= quiet_period:
                    if DEBUG:
                        print(f"[MSF] Output complete ({quiet_period}s quiet)")
                    break

                # If no output yet, wait at least min_wait before giving up
                if not output_lines and elapsed < min_wait:
                    continue

        return '\n'.join(output_lines)

    def execute(self, command: str, timeout: float = 120, quiet_period: float = 2.0) -> str:
        """
        Execute a command in the persistent msfconsole.

        Args:
            command: The msfconsole command to execute
            timeout: Maximum time to wait for response
            quiet_period: How long to wait after last output before returning

        Returns:
            The command output
        """
        with self.lock:
            if not self.process or self.process.poll() is not None:
                if not self.start():
                    return "[ERROR] Failed to start msfconsole"

            # Clear any pending output
            while not self.output_queue.empty():
                try:
                    self.output_queue.get_nowait()
                except queue.Empty:
                    break

            # Send command
            try:
                self.process.stdin.write(command + "\n")
                self.process.stdin.flush()
            except Exception as e:
                return f"[ERROR] Failed to send command: {e}"

            # Collect output
            output = self._wait_for_output(timeout=timeout, quiet_period=quiet_period)
            return output if output else "(no output)"

    def sync_session_ids(self) -> Dict[int, dict]:
        """
        Synchronize internal session_ids set with actual Metasploit state.

        This queries 'sessions -l' and updates the internal tracking to match
        the authoritative state from Metasploit.

        Returns:
            Dict of current sessions {session_id: session_info}
        """
        output = self.execute("sessions -l", timeout=30, quiet_period=3.0)
        # Need to import the helper - it's defined after this class
        # So we call it via module-level function
        cleaned = _clean_ansi_output(output)
        actual_sessions = _parse_sessions_output(cleaned)
        self.session_ids = set(actual_sessions.keys())

        if DEBUG:
            print(f"[MSF] Synced session_ids: {self.session_ids}")

        return actual_sessions

    def stop(self):
        """Stop the msfconsole process."""
        if self.process and self.process.poll() is None:
            try:
                self.process.stdin.write("exit\n")
                self.process.stdin.flush()
                self.process.wait(timeout=5)
            except:
                self.process.kill()
            print("[MSF] msfconsole stopped")
        self.process = None
        self._initialized = False
        self.session_ids.clear()

    def restart(self) -> bool:
        """Restart the msfconsole process completely."""
        print("[MSF] Restarting msfconsole process...")
        self.stop()
        # Clear the output queue
        while not self.output_queue.empty():
            try:
                self.output_queue.get_nowait()
            except queue.Empty:
                break
        return self.start()


# Global singleton instance
_msf_console: Optional[PersistentMsfConsole] = None
_msf_lock = threading.Lock()


def get_msf_console() -> PersistentMsfConsole:
    """Get or create the persistent msfconsole instance."""
    global _msf_console
    with _msf_lock:
        if _msf_console is None:
            _msf_console = PersistentMsfConsole()
            _msf_console.start()
            atexit.register(_msf_console.stop)
        elif not _msf_console._initialized:
            _msf_console.start()
    return _msf_console


# =============================================================================
# HELPER - Timeout and quiet period logic (single place)
# =============================================================================

def _get_timing_for_command(command: str) -> tuple[float, float]:
    """
    Determine timeout and quiet_period based on command type.

    Returns:
        (timeout, quiet_period) tuple
    """
    cmd_lower = command.lower()

    if any(x in cmd_lower for x in ['exploit', 'run']):
        # Exploits: Long timeout for stage transfer, but shorter quiet period.
        # The agent should use msf_wait_for_session() for explicit session polling
        # rather than relying on quiet period to capture session establishment.
        # 30s quiet captures most exploit output while allowing faster response.
        return (300, 30.0)  # Exploits: 5 min timeout, 30s quiet
    elif 'search' in cmd_lower:
        return (60, 3.0)   # Search: 1 min timeout, 3s quiet
    elif 'sessions' in cmd_lower:
        # Sessions commands: shorter quiet for faster polling in msf_wait_for_session
        return (60, 5.0)   # Session commands: 60s timeout, 5s quiet
    elif any(x in cmd_lower for x in ['info', 'show']):
        return (60, 3.0)   # Info/show: 1 min timeout, 3s quiet
    else:
        return (120, 3.0)  # Default: 2 min timeout, 3s quiet


def _clean_ansi_output(text: str) -> str:
    """
    Remove ANSI escape codes and control characters from msfconsole output.
    Handles terminal echo, carriage returns, backspaces, and escape sequences.

    Also removes garbled command echo lines that look like partial typing.
    """
    # Step 1: Remove ANSI escape sequences (colors, cursor movement, etc.)
    text = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', text)
    text = re.sub(r'\x1b\][^\x07]*\x07', '', text)  # OSC sequences
    text = re.sub(r'\x1b[()][AB012]', '', text)  # Character set selection

    # Step 2: Process each line
    cleaned_lines = []
    for line in text.split('\n'):
        # Handle carriage returns - keep only the LAST segment after final \r
        if '\r' in line:
            # The last part after \r is what's actually displayed
            parts = line.split('\r')
            # Filter out empty parts and take the last non-empty one
            non_empty_parts = [p for p in parts if p.strip()]
            if non_empty_parts:
                line = non_empty_parts[-1]
            else:
                line = ''

        # Step 3: Handle backspaces - each \x08 erases previous char
        while '\x08' in line:
            pos = line.find('\x08')
            if pos > 0:
                line = line[:pos-1] + line[pos+1:]
            else:
                line = line[1:]

        # Step 4: Remove other control characters
        line = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', line)

        # Strip whitespace
        line = line.rstrip()

        # Keep meaningful lines
        if line or (cleaned_lines and cleaned_lines[-1]):
            cleaned_lines.append(line)

    # Remove trailing empty lines
    while cleaned_lines and not cleaned_lines[-1]:
        cleaned_lines.pop()

    # Step 5: Remove garbled echo lines (partial command typing artifacts)
    # These look like: "msf exploit(multi/http/apacset PAYLOAD cmd/unix/pyth"
    # or lines starting with "<" which are cursor artifacts
    final_lines = []
    for line in cleaned_lines:
        # Skip lines that start with "<" (cursor movement artifacts)
        if line.startswith('<'):
            continue

        # Skip lines that look like garbled prompt+partial command
        # Pattern: "msf ...>" followed by partial command without space
        # E.g., "msf exploit(multi/http/apacset PAYLOAD" (no space after prompt)
        if re.match(r'^msf\s+\S+>\S', line):
            continue

        # Skip very short partial echo lines (less than 5 chars, not a result line)
        if len(line) < 5 and not line.startswith('[') and '=>' not in line:
            continue

        final_lines.append(line)

    return '\n'.join(final_lines)


def _parse_sessions_output(output: str) -> Dict[int, dict]:
    """
    Parse sessions table from 'sessions -l' output.

    This provides authoritative session state by parsing the actual table output,
    rather than relying on fragile event detection.

    Args:
        output: Raw output from 'sessions -l' command

    Returns:
        Dict mapping session_id to session info:
        {session_id: {'type': str, 'info': str, 'connection': str}}
    """
    sessions = {}
    lines = output.split('\n')
    in_table = False

    for line in lines:
        # Clean the line
        clean_line = line.strip()

        # Detect header row (Id, Name, Type, Information, Connection)
        if 'Id' in clean_line and 'Type' in clean_line:
            in_table = True
            continue

        # Skip separator row (dashes)
        if in_table and clean_line.startswith('--'):
            continue

        # Skip "No active sessions" message
        if 'no active sessions' in clean_line.lower():
            break

        # Parse data rows
        if in_table and clean_line:
            # Split into parts: Id, Name, Type, Information, Connection
            # Use maxsplit to preserve connection string which may have spaces
            parts = clean_line.split(None, 4)

            if len(parts) >= 1 and parts[0].isdigit():
                session_id = int(parts[0])
                sessions[session_id] = {
                    'name': parts[1] if len(parts) > 1 else '',
                    'type': parts[2] if len(parts) > 2 else 'unknown',
                    'info': parts[3] if len(parts) > 3 else '',
                    'connection': parts[4] if len(parts) > 4 else '',
                }

    return sessions


def _execute_msf_command(command: str) -> str:
    """
    Internal function to execute Metasploit commands.
    Single entry point used by all MCP tools.
    """
    if DEBUG:
        print(f"[MSF] Executing: {command[:100]}...")

    msf = get_msf_console()
    timeout, quiet_period = _get_timing_for_command(command)

    if DEBUG:
        print(f"[MSF] timeout={timeout}s, quiet_period={quiet_period}s")

    result = msf.execute(command, timeout=timeout, quiet_period=quiet_period)

    # Clean the output for readability
    result = _clean_ansi_output(result)

    if DEBUG:
        print(f"[MSF] Result ({len(result)} chars)")

    return result


# =============================================================================
# MCP TOOLS
# =============================================================================

@mcp.tool()
def msf_execute(command: str) -> str:
    """
    Execute Metasploit Framework console commands with PERSISTENT state.

    IMPORTANT: This tool maintains state between calls!
    - Module context persists (use exploit/... stays loaded)
    - Sessions persist and can be accessed in later calls
    - You can run commands across multiple tool calls

    The msfconsole process runs continuously in the background.

    Args:
        command: One or more msfconsole commands separated by semicolons.

    Returns:
        The output from msfconsole

    Examples:
        Search: "search CVE-2021-42013"
        Info: "info exploit/multi/http/apache_normalize_path_rce"
        Configure: "use exploit/...; set RHOSTS 10.0.0.5; set RPORT 8080"
        Exploit: "exploit"
        Sessions: "sessions -l"
        Post-exploit: "sessions -c 'whoami' -i 1"
    """
    return _execute_msf_command(command)


@mcp.tool()
def msf_sessions_list() -> str:
    """
    List all active Meterpreter/shell sessions.

    Returns the output of 'sessions -l' from msfconsole,
    showing all active sessions with their details.

    Returns:
        Session list from msfconsole
    """
    return _execute_msf_command("sessions -l")


@mcp.tool()
def msf_session_run(session_id: int, command: str) -> str:
    """
    Run a command on a specific Meterpreter/shell session.

    This tool validates that the session exists before executing the command,
    preventing confusing errors when trying to use a non-existent session.

    Args:
        session_id: The session ID (from sessions -l)
        command: The command to run on the target system

    Returns:
        The command output from the target system, or error if session not found

    Examples:
        msf_session_run(1, "whoami")
        msf_session_run(1, "cat /etc/passwd")
        msf_session_run(1, "id")
    """
    msf = get_msf_console()

    # First, validate session exists
    output = msf.execute("sessions -l", timeout=30, quiet_period=3.0)
    output = _clean_ansi_output(output)
    active_sessions = _parse_sessions_output(output)

    # Update internal tracking
    msf.session_ids = set(active_sessions.keys())

    if session_id not in active_sessions:
        available = sorted(active_sessions.keys()) if active_sessions else "none"
        return (
            f"[ERROR] Session {session_id} not found.\n"
            f"Available sessions: {available}\n"
            "\n"
            "The session may have died or been closed.\n"
            "Use msf_sessions_list to see current sessions, or\n"
            "use msf_wait_for_session if you just ran an exploit."
        )

    # Session exists, execute the command
    safe_command = command.replace("'", "'\\''")
    return _execute_msf_command(f"sessions -c '{safe_command}' -i {session_id}")


@mcp.tool()
def msf_session_close(session_id: int) -> str:
    """
    Close/kill a specific session.

    Args:
        session_id: The session ID to close

    Returns:
        Confirmation of session closure
    """
    return _execute_msf_command(f"sessions -k {session_id}")


@mcp.tool()
def msf_restart() -> str:
    """
    Restart the msfconsole process completely.

    Use this when msfconsole is in a bad state (e.g., stuck in a session,
    commands not working, or returning shell errors like '/bin/sh: command not found').

    This will:
    - Kill the current msfconsole process
    - Start a fresh msfconsole instance
    - Clear all sessions and module state

    Returns:
        Status message indicating success or failure
    """
    msf = get_msf_console()
    if msf.restart():
        return "msfconsole restarted successfully. All sessions cleared, fresh state."
    else:
        return "[ERROR] Failed to restart msfconsole"


@mcp.tool()
def msf_status() -> str:
    """
    Get the current status of the Metasploit console.

    Returns:
        Status info including process state and session count
    """
    msf = get_msf_console()

    if msf.process and msf.process.poll() is None:
        return f"""msfconsole: RUNNING
PID: {msf.process.pid}
Tracked sessions: {len(msf.session_ids)} ({sorted(msf.session_ids) if msf.session_ids else 'none'})

Use 'sessions -l' for full session details."""
    else:
        return "msfconsole: NOT RUNNING"


@mcp.tool()
def msf_wait_for_session(
    timeout: int = 120,
    poll_interval: int = 5,
    expected_session_id: int = None
) -> str:
    """
    Wait for a Meterpreter/shell session to be established after running an exploit.

    Use this tool AFTER running an exploit with a session-based payload (e.g., meterpreter).
    It polls 'sessions -l' repeatedly until a session appears or the timeout is reached.

    This is essential for statefull exploitation because:
    - Stage transfer can take 10-30 seconds (Meterpreter is ~3MB)
    - Session registration in Metasploit can take additional time
    - Simply running 'exploit' and immediately checking 'sessions -l' may miss the session

    Args:
        timeout: Maximum seconds to wait for session (default: 120)
        poll_interval: Seconds between session checks (default: 5)
        expected_session_id: If specified, wait for this specific session ID

    Returns:
        Session details if found, or timeout error with troubleshooting hints

    Example workflow:
        1. Run exploit: metasploit_console("exploit")
        2. Wait for session: msf_wait_for_session(timeout=120)
        3. Use session: msf_session_run(1, "whoami")
    """
    msf = get_msf_console()
    start_time = time.time()
    last_sessions = {}
    attempts = 0

    print(f"[MSF] Waiting for session (timeout={timeout}s, poll={poll_interval}s)")

    while time.time() - start_time < timeout:
        attempts += 1

        # Query sessions with shorter timing for polling
        output = msf.execute("sessions -l", timeout=30, quiet_period=3.0)
        output = _clean_ansi_output(output)
        current_sessions = _parse_sessions_output(output)

        # Update internal tracking
        msf.session_ids = set(current_sessions.keys())

        if DEBUG:
            print(f"[MSF] Poll {attempts}: found {len(current_sessions)} sessions")

        # Check if expected session exists
        if expected_session_id is not None:
            if expected_session_id in current_sessions:
                session = current_sessions[expected_session_id]
                print(f"[MSF] Found expected session {expected_session_id}")
                return (
                    f"Session {expected_session_id} established!\n"
                    f"Type: {session['type']}\n"
                    f"Info: {session['info']}\n"
                    f"Connection: {session['connection']}\n"
                    f"(Found after {attempts} polls, {int(time.time() - start_time)}s)"
                )

        # Check for any new sessions
        new_sessions = set(current_sessions.keys()) - set(last_sessions.keys())
        if new_sessions:
            new_id = min(new_sessions)  # Get lowest new session ID
            session = current_sessions[new_id]
            print(f"[MSF] New session {new_id} detected")
            return (
                f"New session {new_id} established!\n"
                f"Type: {session['type']}\n"
                f"Info: {session['info']}\n"
                f"Connection: {session['connection']}\n"
                f"Total active sessions: {len(current_sessions)}\n"
                f"(Found after {attempts} polls, {int(time.time() - start_time)}s)"
            )

        last_sessions = current_sessions
        time.sleep(poll_interval)

    # Timeout reached
    elapsed = int(time.time() - start_time)
    existing = list(last_sessions.keys()) if last_sessions else "none"

    print(f"[MSF] Session wait timeout after {elapsed}s")

    return (
        f"Timeout after {elapsed}s ({attempts} polls). No new session detected.\n"
        f"Existing sessions: {existing}\n"
        "\n"
        "Possible causes:\n"
        "- Payload couldn't connect back (check LHOST is reachable from target)\n"
        "- Firewall blocking LPORT (try a different port or use bind payload)\n"
        "- Exploit didn't succeed (check exploit output for errors)\n"
        "- Stage transfer still in progress (try longer timeout)\n"
        "- Target killed the payload (AV/EDR detection)\n"
        "\n"
        "Troubleshooting:\n"
        "- Verify LHOST is your attacker IP reachable from target network\n"
        "- Verify LPORT is not blocked and not already in use\n"
        "- Try 'jobs' to see if handler is still listening\n"
        "- Consider using bind payload instead of reverse"
    )


@mcp.tool()
def metasploit_console(command: str) -> str:
    """
    Execute Metasploit Framework console commands.

    NOTE: This is now a STATEFUL tool! Sessions and module context persist.

    Args:
        command: msfconsole command(s) separated by semicolons.

    Returns:
        The output from msfconsole
    """
    return _execute_msf_command(command)


if __name__ == "__main__":
    transport = os.getenv("MCP_TRANSPORT", "stdio")

    if transport == "sse":
        mcp.run(transport="sse", host=SERVER_HOST, port=SERVER_PORT)
    else:
        mcp.run(transport="stdio")
