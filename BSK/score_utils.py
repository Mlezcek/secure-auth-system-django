from .models import TrustedDevice, PasswordResetEvent
from django.utils.timezone import now
from datetime import timedelta

def calculate_security_score(user):
    score = 0
    max_score = 4
    alerts = []

    # MFA włączone
    if user.mfa_enabled:
        score += 1
    else:
        alerts.append({
            'level': 'danger',
            'text': 'Nie masz włączonego MFA. Włącz, aby chronić konto.'
        })

    # Zaufane urządzenia istnieją?
    if TrustedDevice.objects.filter(user=user, is_active=True).exists():
        score += 1
    else:
        alerts.append({
            'level': 'warning',
            'text': 'Nie masz dodanego żadnego zaufanego urządzenia.'
        })

    # Ostatnia zmiana hasła
    last_reset = PasswordResetEvent.objects.filter(user=user).order_by('-timestamp').first()
    if last_reset and (now() - last_reset.timestamp) < timedelta(days=90):
        score += 1
    else:
        alerts.append({
            'level': 'warning',
            'text': 'Hasło nie było zmieniane przez ponad 90 dni.'
        })

    # Ostatnia nieudana próba logowania z innego IP
    recent_failed = user.loginattempt_set.filter(success=False).order_by('-timestamp')[:3]
    if recent_failed:
        suspicious = any(a.ip_address not in [
            e.ip_address for e in user.loginevent_set.order_by('-timestamp')[:5]
        ] for a in recent_failed)
        if not suspicious:
            score += 1
        else:
            alerts.append({
                'level': 'danger',
                'text': 'Wykryto podejrzane nieudane próby logowania z nowych IP.'
            })
    else:
        score += 1

    return int((score / max_score) * 100), alerts
