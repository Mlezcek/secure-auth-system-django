import uuid

import pyotp
import qrcode
import qrcode.image.svg
from io import BytesIO

from django.contrib.auth import login
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.views import View
from django.shortcuts import render, redirect

from BSK.mail import send_new_login_email
from BSK.models import User, LoginEvent, LoginAttempt
from BSK.trusted_device_utils import register_trusted_device, generate_auth_token, get_location_from_ip
from BSK.utils import kill_other_sessions, get_client_ip


class MFASetupView(View):
    def get(self, request):
        user = request.user
        if not user.mfa_secret:
            # Generate new secret
            user.mfa_secret = pyotp.random_base32()
            user.save()
        else:
            # If the secret already exists simply redirect back to the
            # dashboard – the QR code should not be shown again.
            return redirect('dashboard')

        totp = pyotp.TOTP(user.mfa_secret)
        otp_auth_url = totp.provisioning_uri(name=user.email, issuer_name='BSK System')

        # Generate QR code SVG
        import qrcode
        import base64

        img = qrcode.make(otp_auth_url)
        stream = BytesIO()
        img.save(stream, format="PNG")
        img_base64 = base64.b64encode(stream.getvalue()).decode()

        return render(request, 'mfa_setup.html', {
            'img_base64': img_base64,
            'otp_auth_url': otp_auth_url,
        })

class MFAVerifyView(View):
    def get(self, request):
        if 'pre_mfa_user_id' not in request.session:
            return redirect('login')

        return render(request, 'mfa_verify.html')

    def post(self, request):
        user_id = request.session.get('pre_mfa_user_id')
        user = User.objects.get(id=user_id)
        code = request.POST.get('mfa_code')
        ip = get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')

        totp = pyotp.TOTP(user.mfa_secret)
        if totp.verify(code):
            del request.session['pre_mfa_user_id']
            login(request, user)

            LoginAttempt.objects.create(
                user=user,
                username_entered=user.login,
                ip_address=ip,
                user_agent=user_agent,
                success=True,
                mfa_used=True,
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

            kill_other_sessions(user, request.session.session_key)

            # Przygotowujemy redirect jako response
            target = 'change_password' if user.must_change_password else 'dashboard'
            response = redirect(target)

            auth_token = generate_auth_token(str(uuid.uuid4()))  # losowy
            request.session["auth_token"] = auth_token

            if request.POST.get('remember_device'):
                register_trusted_device(response, request, user, token_override=auth_token)
            else:
                response.set_cookie(
                    'auth_token',
                    auth_token,
                    max_age=60 * 15,  # krótki czas, np. 15 min
                    httponly=True,
                    secure=True,
                    samesite='Lax'
                )

            return response
        else:

            LoginAttempt.objects.create(
                user=user,
                username_entered=user.login,
                ip_address=ip,
                user_agent=user_agent,
                success=False,
                mfa_used=True,
            )

            return render(request, 'mfa_verify.html', {
                'error': 'Niepoprawny kod MFA.'
            })
