from unittest.mock import patch
from django.test import TestCase
from django.contrib.auth import get_user_model
from BSK.views import send_new_login_email

class MailTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            login='testuser',
            email='test@example.com',
            password='supersecure'
        )

    @patch('BSK.views.send_new_login_email')
    def test_email_sent_on_new_location(self, mock_send_email):
        ip = '1.2.3.4'
        location = 'Berlin, Germany'

        send_new_login_email(self.user, ip, location)

        mock_send_email.assert_called_once_with(self.user, ip, location)
