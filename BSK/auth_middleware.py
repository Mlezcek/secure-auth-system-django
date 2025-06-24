from django.contrib.auth import logout
from django.utils.deprecation import MiddlewareMixin
from .models import TrustedDevice

class AuthTokenMiddleware(MiddlewareMixin):
    def process_request(self, request):
        if 'auth_token' not in request.session:
            return  # nie sprawdzaj

        if not request.user.is_authenticated:
            return

        cookie_token = request.COOKIES.get('auth_token')
        session_token = request.session.get('auth_token')

        device_id = request.COOKIES.get('trusted_device_id')
        if device_id:
            device = TrustedDevice.objects.filter(
                user=request.user,
                device_id=device_id,
                is_active=True
            ).first()
            if device and device.auth_token == cookie_token:
                # Poprawny token dla zaufanego urządzenia
                return


        # Jeśli niezaufane urządzenie
        if not cookie_token or not session_token or cookie_token != session_token:
            logout(request)