from django.core.mail import send_mail
from BSK import settings


def notify_user_email(user, subject, message):
    if not getattr(user, "email", None):
        return
    send_mail(
        subject,
        message,
        settings.DEFAULT_FROM_EMAIL,
        [user.email],
        fail_silently=True,
    )

def send_password_reset_email(user, reset_link):
    subject = "Resetowanie has\u0142a"
    message = f"Kliknij w link aby zresetowa\u0107 has\u0142o: {reset_link}"
    notify_user_email(user, subject, message)

def send_new_login_email(user, ip_address, location=None):
    subject = "Nowe logowanie do konta"
    message = f"Zalogowano na Twoje konto z IP: {ip_address}"
    if location:
        message += f" ({location})"
    message += ".\nJeśli to nie Ty – zmień hasło i zgłoś incydent."
    notify_user_email(user, subject, message)

def send_account_blocked_email(user, ip_address):
    subject = "Konto zablokowane"
    message = (
        "Twoje konto zosta\u0142o zablokowane po wielu "
        f"nieudanych pr\u00f3bach logowania z IP {ip_address}"
    )
    notify_user_email(user, subject, message)

def send_mfa_reset_email(user):
    subject = "Reset MFA"
    message = "Twoje uwierzytelnianie wielosk\u0142adnikowe zosta\u0142o zresetowane."
    notify_user_email(user, subject, message)