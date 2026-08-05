"""
test_ssh_collector_runner.py
=============================
Unit tests for tools/ssh_collector_runner.py module.
"""

from __future__ import annotations

import base64
import json
from unittest import mock
from tools.ssh_collector_runner import run_collector_over_ssh


def test_run_collector_over_ssh_bundles_common(tmp_path):
    # Create dummy collector script that imports from collectors.common
    collector_file = tmp_path / "test_collector.py"
    collector_file.write_text(
        "import json\n"
        "from collectors.common import read_file\n"
        "print(json.dumps({'test_section': {'status': 'ok'}}))\n",
        encoding="utf-8"
    )

    # Create dummy common.py in same directory
    common_file = tmp_path / "common.py"
    common_file.write_text(
        "def read_file(path):\n"
        "    return 'mock_content'\n",
        encoding="utf-8"
    )

    mock_ssh = mock.MagicMock()
    mock_stdin = mock.MagicMock()
    mock_stdout = mock.MagicMock()
    mock_stderr = mock.MagicMock()

    # Simulate running the payload locally to verify the bootstrap payload works
    def mock_exec_command(cmd, timeout=30):
        # Extract b64payload from command
        start_idx = cmd.find("exec(base64.b64decode('") + len("exec(base64.b64decode('")
        end_idx = cmd.find("').decode())")
        b64_payload = cmd[start_idx:end_idx]
        payload = base64.b64decode(b64_payload).decode("utf-8")

        # Execute payload in a clean namespace with stdout capture
        import io, contextlib
        f = io.StringIO()
        with contextlib.redirect_stdout(f):
            exec(payload, {})
        
        output = f.getvalue()
        mock_stdout.read.return_value = output.encode("utf-8")
        return mock_stdin, mock_stdout, mock_stderr

    mock_ssh.exec_command.side_effect = mock_exec_command

    res = run_collector_over_ssh(
        ssh=mock_ssh,
        script_path=str(collector_file),
        password="",
        timeout=10,
        fallback_key="test_section"
    )

    assert res == {"test_section": {"status": "ok"}}
