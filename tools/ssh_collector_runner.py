"""
ssh_collector_runner.py
=======================
Generic helper for executing a local SENTINEL collector module on a remote
machine via SSH, using a base64-encoded Python payload.

Security note
-------------
The sudo password is delivered exclusively through stdin and the channel
write-end is immediately closed (EOF) to prevent sudo blocking.  The
password is **never** embedded in the shell command string.

Usage
-----
    from tools.ssh_collector_runner import run_collector_over_ssh

    result = run_collector_over_ssh(
        ssh=ssh_client,
        script_path="/abs/path/to/collectors/my_collector.py",
        password="sudo_password",  # pass "" for passwordless sudo
        timeout=30,
        fallback_key="my_section",  # top-level key used in error returns
    )
"""

from __future__ import annotations

import base64
import json
import logging
import os
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import paramiko

log = logging.getLogger(__name__)


def run_collector_over_ssh(
    ssh: "paramiko.SSHClient",
    script_path: str,
    password: str = "",
    timeout: int = 30,
    fallback_key: str = "errors",
) -> dict[str, Any]:
    """
    Read *script_path* from the local filesystem, base64-encode it, and
    execute it on the remote machine via ``sudo python3``.

    The remote script is expected to print a single-line JSON object to stdout.
    The first ``{`` found in stdout begins the JSON payload; everything before
    it (e.g. sudo prompts, motd) is silently discarded.

    Parameters
    ----------
    ssh:
        An authenticated ``paramiko.SSHClient``.
    script_path:
        Absolute path to the local ``.py`` collector file that will be shipped.
    password:
        Sudo password to supply via stdin.  Pass ``""`` for passwordless sudo.
    timeout:
        SSH channel timeout in seconds (default 30).  Increase for heavy scans.
    fallback_key:
        Top-level key used in the error dict returned on failure.

    Returns
    -------
    dict
        On success: the parsed JSON dict from the remote collector.
        On failure: ``{fallback_key: {"errors": [{"check": ..., "error": ...}]}}``
    """
    def _error(check: str, msg: str) -> dict[str, Any]:
        return {fallback_key: {"errors": [{"check": check, "error": msg}]}}

    # 1. Read the local collector script and optional common.py
    try:
        with open(script_path, "r", encoding="utf-8") as f:
            py_script = f.read()
    except Exception as exc:
        return _error("read_collector_script", str(exc))

    common_script = ""
    common_path = os.path.join(os.path.dirname(script_path), "common.py")
    if not os.path.isfile(common_path):
        common_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "collectors", "common.py")
    if os.path.isfile(common_path):
        try:
            with open(common_path, "r", encoding="utf-8") as f:
                common_script = f.read()
        except Exception:
            pass

    # 2. Base64-encode scripts and build the remote command with collectors.common module bootstrap.
    # NOTE: The password is NOT embedded in the command string — it is sent
    # via stdin only, and the channel write-end is closed immediately after.
    b64_script = base64.b64encode(py_script.strip().encode()).decode()
    b64_common = base64.b64encode(common_script.strip().encode()).decode() if common_script else ""

    bootstrap_py = (
        "import base64, sys, types\n"
        f"b64_common = '{b64_common}'\n"
        f"b64_script = '{b64_script}'\n"
        "if b64_common:\n"
        "    try:\n"
        "        common_code = base64.b64decode(b64_common).decode('utf-8')\n"
        "        pkg = types.ModuleType('collectors')\n"
        "        sys.modules['collectors'] = pkg\n"
        "        mod = types.ModuleType('collectors.common')\n"
        "        exec(common_code, mod.__dict__)\n"
        "        sys.modules['collectors.common'] = mod\n"
        "        pkg.common = mod\n"
        "    except Exception:\n"
        "        pass\n"
        "exec(base64.b64decode(b64_script).decode('utf-8'))\n"
    )
    b64_payload = base64.b64encode(bootstrap_py.encode()).decode()

    sudo_prefix = "sudo -S" if password else "sudo -n"
    cmd = f"{sudo_prefix} python3 -c \"import base64,sys;exec(base64.b64decode('{b64_payload}').decode())\""

    # 3. Execute remotely
    try:
        stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
        if password:
            stdin.write(password + "\n")
            stdin.flush()
            stdin.channel.shutdown_write()  # EOF so sudo doesn't block
        out = stdout.read().decode("utf-8", errors="replace")
    except Exception as exc:
        log.debug("ssh_collector_runner: exec failed: %s", exc)
        return _error("ssh_exec", str(exc))

    # 4. Parse JSON — find the first '{' to skip any sudo/motd noise
    start = out.find("{")
    if start == -1:
        return _error("json_parse", f"No JSON object found in output: {out[:200]!r}")
    try:
        return json.loads(out[start:])
    except json.JSONDecodeError as exc:
        return _error("json_parse", str(exc))

