import hashlib
import hmac
import uuid

from . import settings
from .models import TrustedDevice
from django.utils.timezone import now
from django.contrib.gis.geoip2 import GeoIP2
import user_agents

from .network_utils import get_client_ip


TRUSTED_DEVICE_COOKIE_NAME = 'trusted_device_id'

# Ustalamy z requesta device_id z ciasteczka
def get_device_id_from_request(request):
    return request.COOKIES.get(TRUSTED_DEVICE_COOKIE_NAME)

# Ustal lokalizację z IP
def get_location_from_ip(ip_address):
    try:
        g = GeoIP2()
        location = g.city(ip_address)
        city = location.get('city', 'Unknown')
        country = location.get('country_name', 'Unknown')
        return f"{city}, {country}"
    except Exception:
        return "Unknown"

# Ustal device name z User-Agent
def get_device_name(user_agent_str):
    ua = user_agents.parse(user_agent_str)
    return f"{ua.os.family} {ua.os.version_string} - {ua.device.family}"

# Czy pominąć MFA dla tego urządzenia
def should_skip_mfa_for_device(request, user):
    device_id = get_device_id_from_request(request)
    user_agent = request.META.get('HTTP_USER_AGENT', '')
    ip = get_client_ip(request)
    location = get_location_from_ip(ip)

    if not device_id:
        return False

    trusted_device = TrustedDevice.objects.filter(
        user=user,
        device_id=device_id,
        is_active=True
    ).first()

    if not trusted_device:
        return False

    trusted_location_country = trusted_device.first_seen_location.split(",")[-1].strip()
    current_location_country = location.split(",")[-1].strip()

    if trusted_location_country != current_location_country:
        return False  # kraj się zmienił

    if trusted_device.user_agent != user_agent:
        return False

    # Update last_used
    trusted_device.last_used = now()
    trusted_device.save()

    return True

# Dodaj nowe trusted device
def register_trusted_device(response, request, user, token_override=None):
    import hmac
    import hashlib
    from django.conf import settings

    device_id = str(uuid.uuid4())
    user_agent = request.META.get('HTTP_USER_AGENT', '')
    ip = get_client_ip(request)
    location = get_location_from_ip(ip)
    device_name = get_device_name(user_agent)

    # Jeśli token nie został podany — wygeneruj na podstawie device_id
    if token_override is None:
        secret = getattr(settings, 'AUTH_TOKEN_SECRET', 'dev_default_secret')
        auth_token = hmac.new(secret.encode(), device_id.encode(), hashlib.sha256).hexdigest()
    else:
        auth_token = token_override

    # Zapis do bazy
    TrustedDevice.objects.create(
        user=user,
        device_id=device_id,
        device_name=device_name,
        user_agent=user_agent,
        first_seen_ip=ip,
        first_seen_location=location,
        auth_token=auth_token
    )

    # Ciasteczka: device_id i auth_token
    response.set_cookie(
        TRUSTED_DEVICE_COOKIE_NAME,
        device_id,
        max_age=60 * 60 * 24 * 30,  # 30 dni
        httponly=True,
        secure=True,
        samesite='Lax'
    )

    response.set_cookie(
        'auth_token',
        auth_token,
        max_age=60 * 60 * 24 * 30,
        httponly=True,
        secure=True,
        samesite='Lax'
    )


def generate_auth_token(device_id: str):
    secret = getattr(settings, 'AUTH_TOKEN_SECRET', 'hardcoded_dev_secret')
    return hmac.new(secret.encode(), device_id.encode(), hashlib.sha256).hexdigest()


