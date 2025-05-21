from django.test import TestCase
from django.urls import reverse
from django.utils.timezone import now
from BSK.models import LoginAttempt
from django.contrib.auth import get_user_model
User = get_user_model()

class LoginViewTest(TestCase):
    def setUp(self):
        # Create a test user
        self.user = User.objects.create_user(
            login='testuser',
            email='test@test.com',
            password='test123'
        )

    def test_correct_login(self):
        response = self.client.post('/login/', {
            'username': 'testuser',
            'password': 'test123'
        })

        # Assert user is redirected to dashboard after successful login
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, '/dashboard/')

        # Assert user is authenticated after redirection
        response = self.client.get(response.url)
        self.assertTrue(response.wsgi_request.user.is_authenticated)

        # Assert successful LoginAttempt record is created
        self.assertTrue(LoginAttempt.objects.filter(
            user=self.user,
            success=True
        ).exists())

    def test_incorrect_password(self):
        response = self.client.post('/login/', {
            'username': 'testuser',
            'password': 'wrongpassword'
        })

        # Assert no redirect occurs
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Niepoprawne dane logowania')

        # Assert user is not authenticated
        self.assertFalse(response.wsgi_request.user.is_authenticated)

        # Assert failed LoginAttempt record is created
        self.assertTrue(LoginAttempt.objects.filter(
            username_entered='testuser',
            success=False
        ).exists())

    def test_is_blocked_after_5_attempts(self):
        login_data = {
            'username': 'testuser',
            'password': 'wrongpassword'
        }

        # Perform 5 failed login attempts
        for _ in range(5):
            self.client.post('/login/', login_data)

        # Assert user is blocked after exceeding allowed attempts
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_blocked)
        self.assertIsNotNone(self.user.blocked_until)

        # Assert appropriate message is shown
        response = self.client.post('/login/', login_data)
        self.assertContains(response, 'Konto zablokowane')
