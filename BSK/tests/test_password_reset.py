from django.test import TestCase
from django.urls import reverse
from django.utils.timezone import now, timedelta
from django.contrib.auth import get_user_model
from unittest.mock import patch
from BSK.models import ResetPasswordToken
import uuid

User = get_user_model()


class PasswordResetTest(TestCase):
    def setUp(self):
        # Create a test user
        self.user = User.objects.create_user(
            login='testuser',
            email='test@test.com',
            password='test123'
        )

    @patch('BSK.views.verify_recaptcha', return_value=True)
    def test_creates_reset_token_for_valid_email(self, mock_captcha):
        response = self.client.post('/password_reset/', {
            'email': 'test@test.com',
            'g-recaptcha-response': 'dummy'
        })

        # Assert response is successful
        self.assertEqual(response.status_code, 200)

        # Assert reset token is created for the user
        self.assertTrue(ResetPasswordToken.objects.filter(user=self.user).exists())

        @patch('BSK.views.verify_recaptcha', return_value=False)
        def test_no_token_when_captcha_fails(self, mock_captcha):
            response = self.client.post('/password_reset/', {
                'email': 'test@test.com',
                'g-recaptcha-response': 'dummy'
            })

            self.assertEqual(response.status_code, 200)
            self.assertFalse(ResetPasswordToken.objects.filter(user=self.user).exists())
            self.assertContains(response, 'Niepoprawna weryfikacja captcha.')

    def test_resets_password_with_valid_token(self):
        # Manually create a valid reset token
        token = ResetPasswordToken.objects.create(
            user=self.user,
            token=str(uuid.uuid4()),
            expires_at=now() + timedelta(minutes=15)
        )

        # Submit new password using valid token
        response = self.client.post(f'/reset/{token.token}/', {
            'new_password': 'newpassword123'
        })

        # Assert response is successful
        self.assertEqual(response.status_code, 200)

        # Refresh and assert user's password is updated
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('newpassword123'))

        # Refresh and assert token is marked as used
        token.refresh_from_db()
        self.assertTrue(token.is_used)



