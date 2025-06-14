from django.test import TestCase
from django.urls import reverse
from django.contrib.auth import get_user_model
import pyotp
from django.test import TestCase
from django.urls import reverse
from django.utils.timezone import now
from django.core import mail
from BSK.models import LoginAttempt
from django.contrib.auth import get_user_model
User = get_user_model()

User = get_user_model()

class MFATestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            login='testuser',
            email='test@example.com',
            password='Testpass123!'
        )
        self.user.mfa_enabled = True
        self.user.mfa_secret = pyotp.random_base32()
        self.user.save()

    def test_mfa_flow(self):
        # 1. login with username/password
        response = self.client.post(reverse('login'), {
            'username': 'testuser',
            'password': 'Testpass123!'
        })
        self.assertRedirects(response, reverse('mfa_verify'))

        # 2. verify MFA
        totp = pyotp.TOTP(self.user.mfa_secret)
        code = totp.now()

        session = self.client.session
        session['pre_mfa_user_id'] = self.user.id
        session.save()

        response = self.client.post(reverse('mfa_verify'), {
            'mfa_code': code
        })
        self.assertRedirects(response, reverse('dashboard'))
