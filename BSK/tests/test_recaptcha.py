from django.test import TestCase
from unittest.mock import patch, MagicMock
import json
import os

from BSK.utils import verify_recaptcha


class VerifyRecaptchaTest(TestCase):
    @patch.dict(os.environ, {"RECAPTCHA_SECRET_KEY": "secret"})
    @patch("urllib.request.urlopen")
    def test_verify_recaptcha_success(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({"success": True}).encode()
        mock_urlopen.return_value.__enter__.return_value = mock_response

        self.assertTrue(verify_recaptcha("dummy"))

    @patch.dict(os.environ, {"RECAPTCHA_SECRET_KEY": "secret"})
    @patch("urllib.request.urlopen")
    def test_verify_recaptcha_failure(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({"success": False}).encode()
        mock_urlopen.return_value.__enter__.return_value = mock_response

        self.assertFalse(verify_recaptcha("dummy"))


