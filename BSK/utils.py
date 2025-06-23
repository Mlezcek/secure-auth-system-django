from django.utils.timezone import now, timedelta
import os
import json
import urllib.request
import urllib.parse
import re

from requests import Session

from .models import (
    ResetPasswordToken,
    PasswordResetEvent, TrustedDevice,
)

from BSK import settings
from .mail import send_account_blocked_email

from .hibp_utils import is_password_pwned
from .models import AdminAuditLog

MAX_FAILED_ATTEMPTS = 5
BLOCK_DURATION_MINUTES = 15




def verify_recaptcha(token: str):
    secret = getattr(settings, "RECAPTCHA_SECRET_KEY", None) or os.environ.get(
        "RECAPTCHA_SECRET_KEY"
    )
    print("[RECAPTCHA DEBUG] SECRET:", secret)
    print("[RECAPTCHA DEBUG] TOKEN:", token)

    if not secret:
        print("[RECAPTCHA DEBUG] Brak klucza — captcha nie może być zweryfikowana.")
        if settings.DEBUG:
            return True
        return False

    try:
        data = urllib.parse.urlencode({"secret": secret, "response": token}).encode()
        req = urllib.request.Request(
            "https://www.google.com/recaptcha/api/siteverify",
            data=data,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as res:
            result = json.loads(res.read().decode())

        print("[RECAPTCHA DEBUG] RESPONSE FROM GOOGLE:", result)

        return result.get("success", False)

    except Exception as e:
        return False


def check_and_handle_blocking(user, success, ip_address=None, user_agent=""):
    if success:
        user.failed_attempts = 0
        user.blocked_until = None
        user.is_blocked = False
        user.save()
        return None

    # Failed login attempt
    user.failed_attempts += 1
    if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
        if not user.is_blocked:
            user.blocked_until = now() + timedelta(minutes=BLOCK_DURATION_MINUTES)
            user.is_blocked = True
            user.save()
            if user.email:
                send_account_blocked_email(user, ip_address)
        else:
            user.save()
    else:
        user.save()

    if user.blocked_until and user.blocked_until > now():
        return 'Konto zablokowane'

    return None


def is_strong_password(password: str):
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    if not re.search(r"[^A-Za-z0-9]", password):
        return False
    return True


def process_password_reset(
    reset_token: ResetPasswordToken,
    new_password: str,
    ip_address: str | None = None,
    user_agent: str = "",
):
    if not reset_token or not reset_token.is_valid():
        return False, "Token jest nieprawidłowy lub wygasł."

    if not is_strong_password(new_password):
        return False, "Hasło nie spełnia wymagań bezpieczeństwa."

    if is_password_pwned(new_password):
        return False, "To hasło zostało znalezione w znanych wyciekach. Wybierz inne hasło."

    user = reset_token.user
    user.set_password(new_password)
    user.must_change_password = False
    user.save()

    TrustedDevice.objects.filter(user=user).update(auth_token=None)

    reset_token.is_used = True
    reset_token.save()

    PasswordResetEvent.objects.create(
        user=user,
        ip_address=ip_address or "0.0.0.0",
        user_agent=user_agent,
    )
    return True, None

def log_admin_action(admin, action: str, request=None, target_user=None, details=""):
    ip_address = get_client_ip(request) if request else "0.0.0.0"
    AdminAuditLog.objects.create(
        admin=admin,
        action=action,
        target_user=target_user,
        ip_address=ip_address,
        details=details
    )

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0]
    return request.META.get('REMOTE_ADDR')

def kill_other_sessions(user, current_session_key):
    sessions = Session.objects.filter(expire_date__gte=now())
    for session in sessions:
        try:
            data = session.get_decoded()
            if data.get('_auth_user_id') == str(user.id) and session.session_key != current_session_key:
                session.delete()
        except Exception:
            continue