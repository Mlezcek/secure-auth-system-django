import base64
import json
from datetime import timedelta, datetime

from django.contrib.auth import authenticate, login
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required, user_passes_test
from django.db.models import Q
from django.http import HttpResponse, Http404, JsonResponse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django.views.decorators.http import require_POST
from webauthn.helpers.structs import PublicKeyCredentialDescriptor

from .hibp_utils import is_password_pwned
from .mail import send_new_login_email, send_password_reset_email, send_mfa_reset_email
from .score_utils import calculate_security_score
from BSK.backup_codes_utils import generate_backup_codes
from .trusted_device_utils import get_location_from_ip, generate_auth_token

User = get_user_model()

from django.shortcuts import redirect, render
from django.utils.timezone import now, localtime
from django.views import View

from .models import LoginAttempt, LoginEvent, ResetPasswordToken, PasswordResetTokenEvent, BlockedIP, TrustedDevice, \
    BackupCode, AdminAuditLog, WebAuthnKey
from .utils import verify_recaptcha, log_admin_action, kill_other_sessions, is_strong_password
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

        # Sprawdź czy IP jest zablokowane
        blocked_ip = BlockedIP.objects.filter(ip_address=ip).first()
        if blocked_ip and blocked_ip.is_blocked():
            return HttpResponse(
                "To IP jest tymczasowo zablokowane. Spróbuj później.",
                status=429
            )
        elif blocked_ip and not blocked_ip.is_blocked():
            # Auto-usuwanie przeterminowanych blokad IP
            blocked_ip.delete()

        # Sprawdź ile było prób z IP w ostatnim okresie
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

        # Sprawdź użytkownika
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

        # Próba uwierzytelnienia
        auth_user = authenticate(request, username=login_input, password=password)

        # Zapisz próbę logowania
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

            # Sprawdzenie MFA
            from .trusted_device_utils import should_skip_mfa_for_device

            if auth_user.mfa_enabled:
                if should_skip_mfa_for_device(request, auth_user):
                    # Pomin MFA — normalny login
                    login(request, auth_user)
                    # Dodaj LoginEvent (


                    kill_other_sessions(auth_user, request.session.session_key)

                    response = redirect('dashboard')
                    if request.COOKIES.get('auth_token'):
                        response.set_cookie(
                            'auth_token',
                            request.COOKIES.get('auth_token'),
                            max_age=60 * 60 * 24 * 30,
                            httponly=True,
                            secure=True,
                            samesite='Lax'
                        )

                    new_ip = not LoginEvent.objects.filter(user=auth_user, ip_address=ip).exists()

                    LoginEvent.objects.create(
                        user=auth_user,
                        ip_address=ip,
                        user_agent=user_agent,
                        location_info=get_location_from_ip(ip),
                    )
                    new_location = get_location_from_ip(ip)

                    if new_ip and auth_user.email:
                        send_new_login_email(auth_user, ip)

                    return redirect('dashboard')
                else:
                    request.session['pre_mfa_user_id'] = auth_user.id
                    return redirect('mfa_verify')

            # Normalny login (bez MFA)
            login(request, auth_user)
            kill_other_sessions(auth_user, request.session.session_key)
            auth_token = generate_auth_token(str(uuid.uuid4()))
            request.session["auth_token"] = auth_token

            response = redirect('dashboard')
            response.set_cookie(
                'auth_token',
                auth_token,
                max_age=60 * 15,
                httponly=True,
                secure=True,
                samesite='Lax'
            )

            # Logowanie eventu
            new_ip = not LoginEvent.objects.filter(user=auth_user, ip_address=ip).exists()
            LoginEvent.objects.create(
                user=auth_user,
                ip_address=ip,
                user_agent=user_agent,
                location_info = get_location_from_ip(ip),
            )
            if new_ip and auth_user.email:
                send_new_login_email(auth_user, ip)

            return response

        # Nieudane logowanie
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

                log_admin_action(
                    admin=request.user,
                    action="Odblokowanie użytkownika",
                    request=request,
                    target_user=user,
                    details="Ręczne odblokowanie z panelu administratora"
                )

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

@login_required
def dashboard_view(request):
    user = request.user
    score, alerts = calculate_security_score(user)
    recent_success = user.loginattempt_set.filter(success=True).order_by('-timestamp')[:5]
    recent_failed = user.loginattempt_set.filter(success=False).order_by('-timestamp')[:5]
    trusted_devices = user.trusteddevice_set.filter(is_active=True)

    return render(request, 'dashboard.html', {
        'score': score,
        'alerts': alerts,
        'trusted_devices': trusted_devices,
        'recent_success': recent_success,
        'recent_failed': recent_failed,
        'mfa_enabled': user.mfa_enabled,
    })

@login_required
def toggle_mfa(request):
    user = request.user
    if request.method == "POST":
        enable = request.POST.get("enable") == "true"
        user.mfa_enabled = enable
        user.save()

    return redirect('dashboard')

@login_required
def remove_trusted_device(request, device_id):
    device = TrustedDevice.objects.filter(user=request.user, device_id=device_id).first()
    if device:
        device.is_active = False
        device.save()
    return redirect('dashboard')

from django.contrib.auth import logout

@login_required
def logout_view(request):
    logout(request)
    return redirect('login')

@login_required
def backup_codes_view(request):
    if request.method == "POST":
        BackupCode.objects.filter(user=request.user).delete()  # Reset
        codes = generate_backup_codes(request.user)
        return render(request, 'backup_codes.html', {'codes': codes})
    return render(request, 'backup_codes.html', {'codes': None})

@csrf_exempt
def verify_backup_code_view(request):
    if request.method != "POST":
        return JsonResponse({'success': False, 'error': 'Nieprawidłowa metoda'}, status=405)

    try:
        data = json.loads(request.body)
        code_input = data.get("code", "").strip()
        user_id = request.session.get('pre_mfa_user_id')
        if not user_id:
            return JsonResponse({'success': False, 'error': 'Brak użytkownika MFA'}, status=400)

        user = User.objects.get(id=user_id)
        for code in BackupCode.objects.filter(user=user, used=False):
            if code.check_code(code_input):
                code.used = True
                code.save()
                del request.session['pre_mfa_user_id']
                login(request, user)
                return JsonResponse({'success': True, 'redirect_url': '/dashboard/'})

        return JsonResponse({'success': False, 'error': 'Nieprawidłowy kod awaryjny'})

    except Exception as e:
        return JsonResponse({'success': False, 'error': 'Błąd przetwarzania'})

@login_required
def backup_codes_view(request):
    user = request.user

    all_codes = BackupCode.objects.filter(user=user).order_by('-created_at')
    active = all_codes.filter(used=False)
    used = all_codes.filter(used=True)
    last_used = used.first().created_at if used.exists() else None
    last_generated = all_codes.first().created_at if all_codes.exists() else None

    cooldown_active = (
        last_generated and (now() - last_generated).total_seconds() < 300
    )

    context = {
        'active_count': active.count(),
        'used_count': used.count(),
        'last_used': localtime(last_used) if last_used else None,
        'last_generated': localtime(last_generated) if last_generated else None,
        'cooldown': cooldown_active,
    }

    return render(request, 'backup_codes.html', context)

@login_required
def download_backup_codes(request):
    codes = request.session.get('show_backup_codes')
    if not codes:
        return HttpResponse("Brak kodów do pobrania", status=400)

    content = "\n".join(codes)
    filename = f"backup_codes_{datetime.date.today()}.txt"
    response = HttpResponse(content, content_type='text/plain')
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response

@csrf_exempt
@require_POST
@login_required
def generate_backup_codes_ajax(request):
    user = request.user
    last_code = BackupCode.objects.filter(user=user).order_by('-created_at').first()

    if last_code and (now() - last_code.created_at).total_seconds() < 30:
        return JsonResponse({'success': False, 'error': 'Możesz wygenerować nowe kody dopiero za chwilę.'})

    BackupCode.objects.filter(user=user).delete()
    codes = generate_backup_codes(user)

    return JsonResponse({'success': True, 'codes': codes})

@user_passes_test(lambda u: u.is_staff or u.is_superuser)
@login_required
def admin_audit_log_view(request):
    logs = AdminAuditLog.objects.select_related('admin', 'target_user').order_by('-timestamp')[:100]
    return render(request, 'admin_audit_logs.html', {'logs': logs})

@login_required
@user_passes_test(lambda u: u.is_staff or u.is_superuser)
def admin_dashboard_view(request):
    users_data = []
    for u in User.objects.all():
        score, _ = calculate_security_score(u)
        last_login = u.loginevent_set.order_by('-timestamp').first()
        users_data.append({
            'id': u.id,
            'login': u.login,
            'email': u.email,
            'is_blocked': u.is_blocked,
            'score': score,
            'last_login': last_login.timestamp if last_login else None,
        })

    blocked_ips = BlockedIP.objects.filter(blocked_until__gt=now())
    return render(request, 'admin_dashboard.html', {
        'users': users_data,
        'blocked_ips': blocked_ips,
    })

@require_POST
@login_required
@user_passes_test(lambda u: u.is_staff or u.is_superuser)
@csrf_protect
def admin_user_action_view(request):
    from .models import User
    from django.utils.timezone import now, timedelta

    user_id = request.POST.get("user_id")
    action = request.POST.get("action")
    admin = request.user

    try:
        target = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return redirect('admin_dashboard')  # fallback

    #Akcje:
    if action == "unblock":
        target.is_blocked = False
        target.blocked_until = None
        target.failed_attempts = 0
        target.save()
    elif action == "block":
        target.is_blocked = True
        target.blocked_until = now() + timedelta(minutes=15)
        target.save()
    elif action == "reset_mfa":
        target.mfa_enabled = False
        target.mfa_secret = None
        target.save()
    elif action == "reset_attempts":
        target.failed_attempts = 0
        target.save()
    elif action == "force_password":
        target.must_change_password = True
        target.save()

    log_admin_action(
        admin=admin,
        action=f"{action} dla użytkownika",
        request=request,
        target_user=target,
        details="Akcja z widoku admin_user_action_view"
    )

    return redirect('admin_dashboard')

@require_POST
@login_required
@user_passes_test(lambda u: u.is_staff or u.is_superuser)
def admin_block_ip_view(request):
    ip = request.POST.get("ip_address")
    duration_minutes = int(request.POST.get("duration", 15))
    until = now() + timedelta(minutes=duration_minutes)

    if ip:
        BlockedIP.objects.update_or_create(
            ip_address=ip,
            defaults={"blocked_until": until}
        )

    log_admin_action(
        admin=request.user,
        action="Zablokowanie IP",
        request=request,
        details=f"IP: {ip}, czas trwania: {duration_minutes} min"
    )

    return redirect('admin_dashboard')


@require_POST
@login_required
@user_passes_test(lambda u: u.is_staff or u.is_superuser)
def admin_unblock_ip_view(request):
    ip = request.POST.get("ip_address")
    BlockedIP.objects.filter(ip_address=ip).delete()

    log_admin_action(
        admin=request.user,
        action="Odblokowanie IP",
        request=request,
        details=f"IP: {ip}, odblokowane"
    )

    return redirect('admin_dashboard')

@login_required
@user_passes_test(lambda u: u.is_staff or u.is_superuser)
def ajax_search_users(request):
    query = request.GET.get("q", "")
    users = User.objects.filter(
        Q(login__icontains=query) | Q(email__icontains=query)
    ).values("id", "login", "email", "is_blocked")
    return JsonResponse(list(users), safe=False)


@login_required
@user_passes_test(lambda u: u.is_staff or u.is_superuser)
def ajax_search_ips(request):
    query = request.GET.get("q", "")
    ips = BlockedIP.objects.filter(ip_address__icontains=query, blocked_until__gt=now()) \
        .values("ip_address", "blocked_until")
    return JsonResponse(list(ips), safe=False)

@login_required
@user_passes_test(lambda u: u.is_staff or u.is_superuser)
def ajax_search_logs(request):
    from .models import LoginAttempt, PasswordResetEvent, PasswordResetTokenEvent
    query = request.GET.get("q", "").lower()

    events = []

    # LoginAttempt
    for l in LoginAttempt.objects.all():
        if query in l.username_entered.lower() or query in l.ip_address or query in str(l.timestamp):
            events.append({
                "type": "LoginAttempt",
                "user": l.username_entered,
                "status": "✅" if l.success else "❌",
                "ip": l.ip_address,
                "timestamp": l.timestamp.strftime("%Y-%m-%d %H:%M"),
            })

    # PasswordResetEvent
    for r in PasswordResetEvent.objects.all():
        if query in r.user.login.lower() or query in r.ip_address or query in str(r.timestamp):
            events.append({
                "type": "PasswordReset",
                "user": r.user.login,
                "status": "🔒",
                "ip": r.ip_address,
                "timestamp": r.timestamp.strftime("%Y-%m-%d %H:%M"),
            })

    # TokenEvents
    for t in PasswordResetTokenEvent.objects.all():
        if query in t.user.login.lower() or query in t.ip_address or query in str(t.timestamp):
            events.append({
                "type": "ResetTokenRequested",
                "user": t.user.login,
                "status": "📩",
                "ip": t.ip_address,
                "timestamp": t.timestamp.strftime("%Y-%m-%d %H:%M"),
            })

    events = sorted(events, key=lambda e: e["timestamp"], reverse=True)
    return JsonResponse(events, safe=False)

from django.http import JsonResponse
from django.contrib.gis.geoip2 import GeoIP2

def test_geoip(request):
    ip = request.GET.get('ip', '8.8.8.8')
    g = GeoIP2()
    try:
        location = g.city(ip)
    except Exception as e:
        return JsonResponse({'error': str(e)})

    return JsonResponse(location)

@login_required
def reset_mfa_view(request):
    if request.method == "POST":
        user = request.user
        cooldown = getattr(settings, 'MFA_RESET_COOLDOWN_HOURS', 24)
        if user.last_mfa_reset and user.last_mfa_reset > now() - timedelta(hours=cooldown):
            return HttpResponse(
                'Mo\u017cesz resetowa\u0107 MFA tylko raz na 24 godziny.',
                status=429,
            )

        user.mfa_secret = None
        user.mfa_enabled = False
        user.last_mfa_reset = now()
        user.save()
        if user.email:
            send_mfa_reset_email(user)
        return redirect('mfa_setup')
    return render(request, 'confirm_reset_mfa.html')

class RegisterView(View):
    def get(self, request):
        return render(request, 'register.html')

    def post(self, request):
        login_input = request.POST.get('login')
        email = request.POST.get('email')
        password = request.POST.get('password')
        password_confirm = request.POST.get('password_confirm')

        if password != password_confirm:
            return render(request, 'register.html', {
                'error': 'Hasła nie są takie same.'
            })

        if not is_strong_password(password):
            return render(request, 'register.html', {
                'error': 'Hasło nie spełnia wymagań bezpieczeństwa.'
            })

        if is_password_pwned(password):
            return render(request, 'register.html', {
                'error': 'To hasło występuje w znanych wyciekach. Wybierz inne hasło.'
            })

        if User.objects.filter(login=login_input).exists():
            return render(request, 'register.html', {
                'error': 'Login jest już zajęty.'
            })

        if User.objects.filter(email=email).exists():
            return render(request, 'register.html', {
                'error': 'Adres e-mail jest już używany.'
            })

        user = User.objects.create_user(login=login_input, email=email, password=password)
        login(request, user)
        return redirect('dashboard')

class FaceIDLoginView(View):
    def get(self, request):
        return render(request, 'faceid_login.html')

    def post(self, request):
        token = request.POST.get('token')
        ip = get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')

        user = verify_faceid_token(token)

        LoginAttempt.objects.create(
            user=user if user else None,
            username_entered=user.login if user else 'FACEID',
            ip_address=ip,
            user_agent=user_agent,
            success=bool(user),
            mfa_used=False,
        )

        if user:
            login(request, user)
            kill_other_sessions(user, request.session.session_key)
            auth_token = generate_auth_token(str(uuid.uuid4()))
            request.session['auth_token'] = auth_token

            response = redirect('dashboard')
            response.set_cookie(
                'auth_token',
                auth_token,
                max_age=60 * 15,
                httponly=True,
                secure=True,
                samesite='Lax'
            )

            new_ip = not LoginEvent.objects.filter(user=user, ip_address=ip).exists()
            LoginEvent.objects.create(
                user=user,
                ip_address=ip,
                user_agent=user_agent,
                location_info=get_location_from_ip(ip),
            )
            if new_ip and user.email:
                send_new_login_email(user, ip)

            return response

        return render(request, 'faceid_login.html', {
            'error': 'FaceID authentication failed.'
        })

class FaceIDSetupView(View):
    """Allow a logged in user to assign or update their FaceID token."""

    @method_decorator(login_required)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def get(self, request):
        return render(request, 'faceid_setup.html', {
            'current_token': request.user.faceid_token
        })

    def post(self, request):
        token = request.POST.get('token', '').strip()
        user = request.user
        user.faceid_token = token or None
        user.save()
        return redirect('dashboard')


from webauthn.helpers import options_to_json
from webauthn import generate_registration_options, generate_authentication_options, verify_registration_response, verify_authentication_response

from django.views.decorators.csrf import csrf_exempt
from django.middleware.csrf import get_token

@csrf_exempt
@login_required
@csrf_exempt
@login_required
def webauthn_register_options(request):
    rp_id = request.get_host().split(":")[0]
    rp_name = "Panel Użytkownika"
    user_id_bytes = str(request.user.id).encode()

    options = generate_registration_options(
        rp_id=rp_id,
        rp_name=rp_name,
        user_id=user_id_bytes,
        user_name=request.user.login,
    )

    # Zapisz challenge jako string, np. base64 lub hex
    request.session['webauthn_challenge'] = base64.b64encode(options.challenge).decode()

    # Zamień user.id na base64 string dla JS
    options_dict = json.loads(options_to_json(options))
    user_id_bytes = str(request.user.id).encode()
    options_dict['user']['id'] = base64.b64encode(user_id_bytes).decode()
    print("ID base64:", options_dict['user']['id'])
    return JsonResponse(options_dict)


@csrf_exempt
@login_required
def webauthn_register_verify(request):
    data = json.loads(request.body)
    challenge = base64.b64decode(request.session.get('webauthn_challenge'))
    if not challenge:
        return JsonResponse({'error': 'Brak wyzwania'}, status=400)

    try:
        verified = verify_registration_response(
            credential=data,
            expected_challenge=challenge,
            expected_rp_id=request.get_host(),
            expected_origin=f"https://{request.get_host()}",
        )

        WebAuthnKey.objects.create(
            user=request.user,
            credential_id=verified.credential_id,
            public_key=verified.credential_public_key,
            sign_count=verified.sign_count
        )
        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)


@csrf_exempt
def webauthn_login_options(request):
    login = request.GET.get('username')
    user = User.objects.filter(login=login).first()
    if not user:
        return JsonResponse({'error': 'Nie znaleziono użytkownika'}, status=404)

    keys = WebAuthnKey.objects.filter(user=user)
    allow_credentials = [
        PublicKeyCredentialDescriptor(id=bytes.fromhex(k.credential_id), type='public-key')
        for k in keys
    ]

    rp_id = request.get_host().split(':')[0]

    options = generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=allow_credentials,
    )

    # 🔒 Zamiana bytes na base64 przed zapisem do sesji
    challenge_b64 = base64.b64encode(options.challenge).decode('utf-8')
    request.session['webauthn_challenge'] = challenge_b64
    request.session['webauthn_login_user'] = user.id

    from webauthn.helpers import options_to_json
    return JsonResponse(json.loads(options_to_json(options)))


@csrf_exempt
def webauthn_login_verify(request):
    data = json.loads(request.body)
    challenge = base64.b64decode(request.session.get('webauthn_challenge', ''))
    user_id = request.session.get('webauthn_login_user')
    if not challenge or not user_id:
        return JsonResponse({'error': 'Brak danych sesji'}, status=400)

    user = User.objects.get(id=user_id)
    key = WebAuthnKey.objects.filter(user=user, credential_id=data['id']).first()
    if not key:
        return JsonResponse({'error': 'Nieprawidłowy klucz'}, status=403)

    try:
        verified = verify_authentication_response(
            credential=data,
            expected_challenge=challenge,
            expected_rp_id=request.get_host(),
            expected_origin=f"https://{request.get_host()}",
            credential_public_key=key.public_key,
            credential_current_sign_count=key.sign_count
        )

        key.sign_count = verified.new_sign_count
        key.save()

        login(request, user)
        return JsonResponse({'success': True, 'redirect_url': '/dashboard/'})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)