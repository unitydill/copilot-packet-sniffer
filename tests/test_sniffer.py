import unittest
import sys
import os

sys.path.insert(
    0,
    os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
)

from sniffer import redact_ip, redact_sensitive


class TestRedaction(unittest.TestCase):

    def test_ip_redaction(self):
        self.assertEqual(
            redact_ip("192.168.1.25"),
            "192.168.1.xxx"
        )

    def test_email_redaction(self):
        result = redact_sensitive(
            "Contact student@example.com"
        )

        self.assertEqual(
            result,
            "Contact [REDACTED_EMAIL]"
        )

    def test_password_redaction(self):
        result = redact_sensitive(
            "password=Secret123"
        )

        self.assertEqual(
            result,
            "password=[REDACTED]"
        )

    def test_token_redaction(self):
        result = redact_sensitive(
            "token=abc123"
        )

        self.assertEqual(
            result,
            "token=[REDACTED]"
        )

    def test_authorization_redaction(self):
        result = redact_sensitive(
            "Authorization: Bearer secret-token"
        )

        self.assertEqual(
            result,
            "Authorization: [REDACTED]"
        )


if __name__ == "__main__":
    unittest.main()
