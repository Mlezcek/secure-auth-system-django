from django.utils.timezone import now, timedelta
import os
import json
import urllib.request
import urllib.parse
import re
from .models import ResetPasswordToken

from BSK import settings

MAX_FAILED_ATTEMPTS = 5
BLOCK_DURATION_MINUTES = 15




def verify_recaptcha(token: str):
    secret = getattr(settings, "RECAPTCHA_SECRET_KEY", None)
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


def check_and_handle_blocking(user, success):
    if success:
        user.failed_attempts = 0
        user.blocked_until = None
        user.is_blocked = False
        user.save()
        return None

    # Failed login attempt
    user.failed_attempts += 1
    if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
        user.blocked_until = now() + timedelta(minutes=BLOCK_DURATION_MINUTES)
        user.is_blocked = True
    user.save()

    if user.blocked_until and user.blocked_until > now():
        return 'Konto zablokowane'

    return None

