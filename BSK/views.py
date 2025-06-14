from datetime import timedelta

from django.contrib.auth import authenticate, login
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required, user_passes_test
from django.http import HttpResponse, Http404
from django.utils.decorators import method_decorator

from .mail import send_new_login_email, send_password_reset_email

User = get_user_model()

from django.shortcuts import redirect, render
from django.utils.timezone import now
from django.views import View

from .models import LoginAttempt, LoginEvent, ResetPasswordToken, PasswordResetTokenEvent, BlockedIP
from .utils import check_and_handle_blocking, verify_recaptcha
from .utils import check_and_handle_blocking, process_password_reset

from django.conf import settings
from django.urls import reverse
import uuid

class LoginView(View):
    def get(self, request):
        return render(request, 'login.html')

    def post(self, request):
        login_input = request.POST.get('username')
        password = request.POST.get('password')
        ip = get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')

        from django.utils.timezone import now
        from datetime import timedelta
        from django.conf import settings
        from .models import BlockedIP

        # Ustawienia rate limitu
        RATE_LIMIT_IP_THRESHOLD = getattr(settings, 'RATE_LIMIT_IP_THRESHOLD', 10)
        RATE_LIMIT_IP_PERIOD_MINUTES = getattr(settings, 'RATE_LIMIT_IP_PERIOD_MINUTES', 1)
        BLOCK_IP_DURATION_MINUTES = getattr(settings, 'BLOCK_IP_DURATION_MINUTES', 15)

        # 1️⃣ Sprawdź czy IP jest zablokowane
        blocked_ip = BlockedIP.objects.filter(ip_address=ip).first()
        if blocked_ip and blocked_ip.is_blocked():
            return HttpResponse(
                "To IP jest tymczasowo zablokowane. Spróbuj później.",
                status=429
            )
        elif blocked_ip and not blocked_ip.is_blocked():
            # Auto-usuwanie przeterminowanych blokad IP
            blocked_ip.delete()

        # 2️⃣ Sprawdź ile było prób z IP w ostatnim okresie
        recent_attempts_count = LoginAttempt.objects.filter(
            ip_address=ip,
            timestamp__gte=now() - timedelta(minutes=RATE_LIMIT_IP_PERIOD_MINUTES)
        ).count()

        if recent_attempts_count >= RATE_LIMIT_IP_THRESHOLD:
            # Zablokuj IP
            BlockedIP.objects.update_or_create(
                ip_address=ip,
                defaults={'blocked_until': now() + timedelta(minutes=BLOCK_IP_DURATION_MINUTES)}
            )
            return HttpResponse(
                "Za dużo prób logowania z tego IP. IP zostało tymczasowo zablokowane.",
                status=429
            )

        # 3️⃣ Sprawdź użytkownika
        user = User.objects.filter(login=login_input).first()

        if user:
            block_message = check_and_handle_blocking(
                user,
                success=False,
                ip_address=ip,
                user_agent=user_agent,
            )
            if block_message:
                return render(
                    request,
                    'login.html',
                    {'error': block_message},
                    status=423  # 423 Locked – RFC 4918
                )

        # 4️⃣ Próba uwierzytelnienia
        auth_user = authenticate(request, username=login_input, password=password)

        # 5️⃣ Zapisz próbę logowania
        LoginAttempt.objects.create(
            user=user if user else None,
            username_entered=login_input,
            ip_address=ip,
            user_agent=user_agent,
            success=bool(auth_user),
            mfa_used=False
        )

        if auth_user:
            # Reset failed attempts jeśli sukces
            check_and_handle_blocking(auth_user, success=True)

            # 6️⃣ Sprawdzenie MFA
            from .trusted_device_utils import should_skip_mfa_for_device

            if auth_user.mfa_enabled:
                if should_skip_mfa_for_device(request, auth_user):
                    # Pomin MFA — normalny login
                    login(request, auth_user)
                    # Dodaj LoginEvent (jak normalnie)
                    new_ip = not LoginEvent.objects.filter(user=auth_user, ip_address=ip).exists()
                    LoginEvent.objects.create(
                        user=auth_user,
                        ip_address=ip,
                        user_agent=user_agent,
                    )
                    if new_ip and auth_user.email:
                        send_new_login_email(auth_user, ip)

                    return redirect('dashboard')
                else:
                    request.session['pre_mfa_user_id'] = auth_user.id
                    return redirect('mfa_verify')

            # 7️⃣ Normalny login (bez MFA)
            login(request, auth_user)

            # Logowanie eventu
            new_ip = not LoginEvent.objects.filter(user=auth_user, ip_address=ip).exists()
            LoginEvent.objects.create(
                user=auth_user,
                ip_address=ip,
                user_agent=user_agent,
            )
            if new_ip and auth_user.email:
                send_new_login_email(auth_user, ip)

            return redirect('dashboard')

        # 8️⃣ Nieudane logowanie
        return render(request, 'login.html', {
            'error': 'Niepoprawne dane logowania.'
        })

class PasswordResetRequestView(View):
    def get(self, request):
        context = {'site_key': settings.RECAPTCHA_SITE_KEY}
        return render(request, 'password_reset_request.html', context)

    def post(self, request):
        captcha = request.POST.get('g-recaptcha-response')
        if not verify_recaptcha(captcha):
            context = {
                'error': 'Niepoprawna weryfikacja captcha.',
                'site_key': settings.RECAPTCHA_SITE_KEY
            }
            return render(request, 'password_reset_request.html', context)
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

            ip = get_client_ip(request)
            user_agent = request.META.get('HTTP_USER_AGENT', '')
            PasswordResetTokenEvent.objects.create(
                user=user,
                ip_address=ip,
                user_agent=user_agent,
            )

            print(f"Reset link: http://localhost:8000/reset/{token}/")
            reset_link = request.build_absolute_uri(
                reverse("password_reset_confirm", args=[token])
            )
            send_password_reset_email(user, reset_link)

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
        ip = get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        success, error = process_password_reset(
            reset_token,
            new_password,
            ip,
            user_agent,
        )

        if not success:
            return render(request, 'password_reset_confirm.html', {
                'token': token,
                'error': error
            })

        return render(request, 'password_reset_complete.html')


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0]
    return request.META.get('REMOTE_ADDR')


def dashboard_view(request):
    return HttpResponse("Zalogowano poprawnie – dashboard")


class BlockedUsersAdminView(View):
    @method_decorator(login_required)
    @method_decorator(user_passes_test(lambda u: u.is_staff or u.is_superuser))
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def get(self, request):
        users = User.objects.filter(is_blocked=True, blocked_until__gt=now())
        return render(request, 'blocked_users.html', {'users': users})

    def post(self, request):
        user_id = request.POST.get('unblock_user_id')
        message = None
        if user_id:
            try:
                user = User.objects.get(id=user_id)
                user.is_blocked = False
                user.blocked_until = None
                user.failed_attempts = 0
                user.save()
                message = 'Użytkownik odblokowany.'
            except User.DoesNotExist:
                message = 'Użytkownik nie istnieje.'
        users = User.objects.filter(is_blocked=True, blocked_until__gt=now())
        return render(request, 'blocked_users.html', {'users': users, 'message': message})

class BlockedIPsAdminView(View):
    @method_decorator(login_required)
    @method_decorator(user_passes_test(lambda u: u.is_staff or u.is_superuser))
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def get(self, request):
        # Lista IP które są jeszcze faktycznie zablokowane
        blocked_ips = BlockedIP.objects.filter(blocked_until__gt=now())
        return render(request, 'blocked_ips.html', {'blocked_ips': blocked_ips})

    def post(self, request):
        ip_to_unblock = request.POST.get('unblock_ip_address')
        message = None
        if ip_to_unblock:
            try:
                blocked_ip = BlockedIP.objects.get(ip_address=ip_to_unblock)
                blocked_ip.delete()
                message = f'Adres IP {ip_to_unblock} został odblokowany.'
            except BlockedIP.DoesNotExist:
                message = 'Podany adres IP nie jest zablokowany.'

        blocked_ips = BlockedIP.objects.filter(blocked_until__gt=now())
        return render(request, 'blocked_ips.html', {
            'blocked_ips': blocked_ips,
            'message': message
        })

