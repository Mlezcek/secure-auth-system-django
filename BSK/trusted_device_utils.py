import uuid
from .models import TrustedDevice
from django.utils.timezone import now
from django.contrib.gis.geoip2 import GeoIP2
import user_agents

from .views import get_client_ip

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

# Czy pominąć MFA dla tego urządzenia?
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

    # Możesz dodać dodatkowe warunki np. UA ≈ OK, lokalizacja ≈ OK
    # Prosty przykład — akceptujemy jeśli kraj się nie zmienił
    trusted_location_country = trusted_device.first_seen_location.split(",")[-1].strip()
    current_location_country = location.split(",")[-1].strip()

    if trusted_location_country != current_location_country:
        return False  # kraj się zmienił → wymuś MFA

    # Możesz dodać też prostą kontrolę User-Agent (tu bardzo prosto)
    if trusted_device.user_agent != user_agent:
        return False

    # Update last_used
    trusted_device.last_used = now()
    trusted_device.save()

    return True

# Dodaj nowe trusted device
def register_trusted_device(response, request, user):
    device_id = str(uuid.uuid4())
    user_agent = request.META.get('HTTP_USER_AGENT', '')
    ip = get_client_ip(request)
    location = get_location_from_ip(ip)
    device_name = get_device_name(user_agent)

    TrustedDevice.objects.create(
        user=user,
        device_id=device_id,
        device_name=device_name,
        user_agent=user_agent,
        first_seen_ip=ip,
        first_seen_location=location
    )

    # Ustaw cookie
    response.set_cookie(
        TRUSTED_DEVICE_COOKIE_NAME,
        device_id,
        max_age=60 * 60 * 24 * 30,  # 30 dni
        httponly=True,
        secure=True,
        samesite='Lax'
    )


