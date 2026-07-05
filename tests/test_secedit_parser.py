"""
test_secedit_parser.py
======================
Unit tests for tools/secedit_parser.py
"""

import unittest
from tools.secedit_parser import parse_password_policy

class TestSeceditParser(unittest.TestCase):

    def test_parse_sample_input(self):
        sample = """
[Unicode]
Unicode=yes
[System Access]
MinimumPasswordAge = 1
MaximumPasswordAge = 42
MinimumPasswordLength = 8
PasswordComplexity = 1
PasswordHistorySize = 24
LockoutBadCount = 5
LockoutDuration = 30
ResetLockoutCount = 30
RequireLogonToChangePassword = 0
ClearTextPassword = 0
[Registry Values]
signature="$CHICAGO$"
"""
        result = parse_password_policy(sample)
        self.assertEqual(result["MinimumPasswordAge"], 1)
        self.assertEqual(result["MaximumPasswordAge"], 42)
        self.assertEqual(result["MinimumPasswordLength"], 8)
        self.assertEqual(result["PasswordComplexity"], 1)
        self.assertEqual(result["PasswordHistorySize"], 24)
        self.assertEqual(result["LockoutBadCount"], 5)
        self.assertEqual(result["LockoutDuration"], 30)
        self.assertEqual(result["ResetLockoutCount"], 30)
        self.assertEqual(result["RequireLogonToChangePassword"], 0)
        self.assertEqual(result["ClearTextPassword"], 0)

    def test_missing_keys_set_to_none(self):
        sample = """
[System Access]
MinimumPasswordLength = 12
PasswordComplexity = 1
"""
        result = parse_password_policy(sample)
        self.assertEqual(result["MinimumPasswordLength"], 12)
        self.assertEqual(result["PasswordComplexity"], 1)
        # Missing keys should be None
        self.assertIsNone(result["MinimumPasswordAge"])
        self.assertIsNone(result["MaximumPasswordAge"])
        self.assertIsNone(result["PasswordHistorySize"])
        self.assertIsNone(result["LockoutBadCount"])
        self.assertIsNone(result["LockoutDuration"])
        self.assertIsNone(result["ResetLockoutCount"])
        self.assertIsNone(result["RequireLogonToChangePassword"])
        self.assertIsNone(result["ClearTextPassword"])

    def test_case_insensitivity_and_whitespace(self):
        sample = "\r\n[SYSTEM ACCESS]\r\n  minimumPasswordLength   =   12  \r\n"
        result = parse_password_policy(sample)
        self.assertEqual(result["MinimumPasswordLength"], 12)

    def test_ignore_other_sections(self):
        sample = """
[Registry Values]
MinimumPasswordLength = 99
[System Access]
MinimumPasswordLength = 8
[Version]
MinimumPasswordLength = 44
"""
        result = parse_password_policy(sample)
        self.assertEqual(result["MinimumPasswordLength"], 8)

    def test_non_integer_values_resilience(self):
        sample = """
[System Access]
MinimumPasswordLength = abc
PasswordComplexity = 1
"""
        result = parse_password_policy(sample)
        self.assertIsNone(result["MinimumPasswordLength"])
        self.assertEqual(result["PasswordComplexity"], 1)

if __name__ == "__main__":
    unittest.main()
