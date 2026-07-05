"""
test_main_win.py
================
Unit tests for main_win.py using mocks.
"""

import unittest
from unittest.mock import patch, MagicMock
from winrm.exceptions import WinRMTransportError, WinRMOperationTimeoutError
from main_win import collect_password_policy, CollectorConnectionError, run_compliance_check


class TestMainWinCollector(unittest.TestCase):

    @patch("main_win.winrm.Session")
    def test_collect_password_policy_success(self, mock_session_class):
        # Set up mocks for WinRM responses
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        # Mock responses
        # Response 1: secedit /export
        resp_export = MagicMock()
        resp_export.status_code = 0
        resp_export.std_out = b""
        resp_export.std_err = b""

        # Response 2: type C:\Windows\Temp\sentinel_secpol.cfg
        resp_type = MagicMock()
        resp_type.status_code = 0
        resp_type.std_out = b"[System Access]\nMinimumPasswordLength = 8\n"
        resp_type.std_err = b""

        # Response 3: del C:\Windows\Temp\sentinel_secpol.cfg
        resp_del = MagicMock()
        resp_del.status_code = 0
        resp_del.std_out = b""
        resp_del.std_err = b""

        mock_session.run_cmd.side_effect = [resp_export, resp_type, resp_del]

        result = collect_password_policy(
            host="192.168.1.100",
            username="Auditor",
            password="SecurePassword123"
        )

        self.assertEqual(result["status"], "partial")  # Only MinimumPasswordLength is non-None
        self.assertEqual(result["source"], "secedit_export")
        self.assertEqual(result["host"], "192.168.1.100")
        self.assertEqual(result["data"]["MinimumPasswordLength"], 8)
        self.assertIsNone(result["data"]["MaximumPasswordAge"])
        self.assertIsNone(result["error"])

        # Check mock calls
        self.assertEqual(mock_session.run_cmd.call_count, 3)

    @patch("main_win.winrm.Session")
    def test_collect_password_policy_export_cmd_fail(self, mock_session_class):
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        # Export returns non-zero status
        resp_export = MagicMock()
        resp_export.status_code = 1
        resp_export.std_err = b"Access Denied"

        mock_session.run_cmd.return_value = resp_export

        with self.assertRaises(RuntimeError) as context:
            collect_password_policy(
                host="192.168.1.100",
                username="Auditor",
                password="WrongPassword"
            )

        self.assertIn("secedit export command failed with status 1", str(context.exception))
        self.assertIn("Access Denied", str(context.exception))

    @patch("main_win.winrm.Session")
    def test_collect_password_policy_transport_error(self, mock_session_class):
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        # run_cmd raises WinRMTransportError
        mock_session.run_cmd.side_effect = WinRMTransportError("transport", "Timeout or connection reset")

        with self.assertRaises(CollectorConnectionError) as context:
            collect_password_policy(
                host="192.168.1.100",
                username="Auditor",
                password="Password"
            )

        self.assertIn("WinRM transport/timeout error for host 192.168.1.100", str(context.exception))

    @patch("main_win.winrm.Session")
    def test_collect_password_policy_non_fatal_cleanup_error(self, mock_session_class):
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        # Response 1: secedit /export
        resp_export = MagicMock()
        resp_export.status_code = 0
        resp_export.std_out = b""

        # Response 2: type config
        resp_type = MagicMock()
        resp_type.status_code = 0
        resp_type.std_out = b"[System Access]\nMinimumPasswordLength = 12\n"

        # Response 3: del command returns non-zero
        resp_del = MagicMock()
        resp_del.status_code = 1
        resp_del.std_err = b"File not found"

        mock_session.run_cmd.side_effect = [resp_export, resp_type, resp_del]

        # The function should NOT fail, cleanup failure is non-fatal
        result = collect_password_policy(
            host="192.168.1.100",
            username="Auditor",
            password="SecurePassword123"
        )

        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["data"]["MinimumPasswordLength"], 12)
        self.assertIsNone(result["error"])

    @patch("main_win.generate_compliance_report")
    def test_run_compliance_check_success(self, mock_report):
        mock_report.return_value = "Mock compliance report text"

        with patch("builtins.open", unittest.mock.mock_open(read_data="# CIS Windows rules")):
            with patch("os.path.isfile", return_value=True):
                result = run_compliance_check(
                    collection_result={"status": "success", "data": {"MinimumPasswordLength": 8}},
                    cis_rules_path="dummy_path.md"
                )

        self.assertEqual(result, "Mock compliance report text")
        mock_report.assert_called_once_with(
            '{\n  "MinimumPasswordLength": 8\n}',
            "# CIS Windows rules"
        )

    @patch("main_win.generate_compliance_report")
    def test_run_compliance_check_missing_file(self, mock_report):
        with patch("os.path.isfile", return_value=False):
            result = run_compliance_check(
                collection_result={"status": "success", "data": {}},
                cis_rules_path="nonexistent.md"
            )
        self.assertIsNone(result)
        mock_report.assert_not_called()


if __name__ == "__main__":
    unittest.main()
