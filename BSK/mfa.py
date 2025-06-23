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

from BSK.models import User
from BSK.trusted_device_utils import register_trusted_device, generate_auth_token
from BSK.utils import kill_other_sessions


class MFASetupView(View):
    def get(self, request):
        user = request.user
        if not user.mfa_secret:
            # Generate new secret
            user.mfa_secret = pyotp.random_base32()
            user.save()

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

        totp = pyotp.TOTP(user.mfa_secret)
        if totp.verify(code):
            del request.session['pre_mfa_user_id']
            login(request, user)

            kill_other_sessions(user, request.session.session_key)

            # Przygotowujemy redirect jako response
            response = redirect('dashboard')

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
            return render(request, 'mfa_verify.html', {
                'error': 'Niepoprawny kod MFA.'
            })
