from django.db import models
from django.utils import timezone
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
import uuid

class CustomUserManager(BaseUserManager):
    def create_user(self, login, password=None, **extra_fields):
        if not login:
            raise ValueError('Użytkownik musi mieć login')
        user = self.model(login=login, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, login, password=None, **extra_fields):
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(login, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    login = models.CharField(max_length=150, unique=True)
    email = models.EmailField(unique=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    failed_attempts = models.IntegerField(default=0)
    is_blocked = models.BooleanField(default=False)
    blocked_until = models.DateTimeField(null=True, blank=True)
    date_joined = models.DateTimeField(default=timezone.now)
    mfa_enabled = models.BooleanField(default=False)

    USERNAME_FIELD = 'login'
    REQUIRED_FIELDS = ['email']

    objects = CustomUserManager()

    def __str__(self):
        return self.login

    def is_currently_blocked(self):
        return self.is_blocked and self.blocked_until and self.blocked_until > timezone.now()


class LoginAttempt(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    username_entered = models.CharField(max_length=150)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    success = models.BooleanField(default=False)
    timestamp = models.DateTimeField(default=timezone.now)
    mfa_used = models.BooleanField(default=False)

    def __str__(self):
        return f"LoginAttempt by {self.username_entered} at {self.timestamp} - {'Success' if self.success else 'Fail'}"


class LoginEvent(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    timestamp = models.DateTimeField(default=timezone.now)
    device_name = models.CharField(max_length=255, blank=True, null=True)
    location_info = models.CharField(max_length=255, blank=True, null=True)

    def __str__(self):
        return f"LoginEvent: {self.user.login} at {self.timestamp}"

class ResetPasswordToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.CharField(max_length=64, unique=True, default=uuid.uuid4)
    created_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)

    def is_valid(self):
        return not self.is_used and self.expires_at > timezone.now()

    def __str__(self):
        return f"Reset token for {self.user.login} (valid: {self.is_valid()})"


class PasswordResetTokenEvent(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    timestamp = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"PasswordResetTokenEvent: {self.user.login} at {self.timestamp}"


class PasswordResetEvent(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    timestamp = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"PasswordResetEvent: {self.user.login} at {self.timestamp}"


class TrustedDevice(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    device_id = models.CharField(max_length=64, unique=True)  # np. losowy UUID zapisany w ciasteczku
    device_name = models.CharField(max_length=255)
    user_agent = models.TextField()
    first_seen_ip = models.GenericIPAddressField()
    first_seen_location = models.CharField(max_length=255, blank=True, null=True)
    last_used = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(default=timezone.now)
    is_active = models.BooleanField(default=True)