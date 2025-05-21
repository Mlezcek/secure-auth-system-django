from datetime import timedelta

from django.contrib.auth import authenticate, login
from django.contrib.auth import get_user_model
from django.http import HttpResponse, Http404

User = get_user_model()

from django.shortcuts import redirect, render
from django.utils.timezone import now
from django.views import View

from .models import LoginAttempt, LoginEvent, ResetPasswordToken
from .utils import check_and_handle_blocking
import uuid

class LoginView(View):
    def get(self, request):
        return render(request, 'login.html')

    def post(self, request):
        login_input = request.POST.get('username')
        password = request.POST.get('password')
        ip = get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')

        user = User.objects.filter(login=login_input).first()

        if user:
            block_message = check_and_handle_blocking(user, success=False)
            if block_message:
                return render(request, 'login.html', {'error': block_message})

        auth_user = authenticate(request, username=login_input, password=password)

        LoginAttempt.objects.create(
            user=user if user else None,
            username_entered=login_input,
            ip_address=ip,
            user_agent=user_agent,
            success=bool(auth_user),
            mfa_used=False
        )

        if auth_user:
            login(request, auth_user)

            check_and_handle_blocking(auth_user, success=True)

            LoginEvent.objects.create(
                user=auth_user,
                ip_address=ip,
                user_agent=user_agent
            )

            return redirect('dashboard')

        return render(request, 'login.html', {
            'error': 'Niepoprawne dane logowania.'
        })
class PasswordResetRequestView(View):
    def get(self, request):
        return render(request, 'password_reset_request.html')

    def post(self, request):
        email = request.POST.get('email')
        user = User.objects.filter(email=email).first()

        if user:
            token = str(uuid.uuid4())
            expires = now() + timedelta(minutes=15)
            ResetPasswordToken.objects.create(
                user=user,
                token=token,
                expires_at=expires
            )

            print(f"Reset link: http://localhost:8000/reset/{token}/")

        return render(request, 'password_reset_requested.html')

class PasswordResetConfirmView(View):
    def get(self, request, token):
        reset_token = ResetPasswordToken.objects.filter(token=token).first()
        if not reset_token or not reset_token.is_valid():
            raise Http404("Token jest nieprawidłowy lub wygasł.")

        return render(request, 'password_reset_confirm.html', {'token': token})

    def post(self, request, token):
        reset_token = ResetPasswordToken.objects.filter(token=token).first()
        if not reset_token or not reset_token.is_valid():
            raise Http404("Token jest nieprawidłowy lub wygasł.")

        new_password = request.POST.get('new_password')
        user = reset_token.user
        user.set_password(new_password)
        user.save()

        reset_token.is_used = True
        reset_token.save()

        return render(request, 'password_reset_complete.html')


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0]
    return request.META.get('REMOTE_ADDR')


def dashboard_view(request):
    return HttpResponse("Zalogowano poprawnie – dashboard")
