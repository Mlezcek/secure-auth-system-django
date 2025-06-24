
from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from BSK.models import (
    LoginAttempt, LoginEvent, PasswordResetEvent,
    PasswordResetTokenEvent, AdminAuditLog
)

class Command(BaseCommand):
    help = "Usuwa wpisy starsze niż 90 dni"

    def handle(self, *args, **options):
        cutoff = timezone.now() - timedelta(days=90)
        LoginAttempt.objects.filter(timestamp__lt=cutoff).delete()
        LoginEvent.objects.filter(timestamp__lt=cutoff).delete()
        PasswordResetEvent.objects.filter(timestamp__lt=cutoff).delete()
        PasswordResetTokenEvent.objects.filter(timestamp__lt=cutoff).delete()
        AdminAuditLog.objects.filter(timestamp__lt=cutoff).delete()
        self.stdout.write(self.style.SUCCESS("Usunięto stare wpisy"))