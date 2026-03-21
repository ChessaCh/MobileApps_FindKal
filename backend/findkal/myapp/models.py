import uuid
import random
from django.db import models
from django.utils import timezone
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin

OTP_EXPIRY_MINUTES = 10
RESET_TOKEN_EXPIRY_MINUTES = 15


class UserManager(BaseUserManager):
    def create_user(self, email, name, password=None, **extra_fields):
        if not email:
            raise ValueError("Email is required")
        email = self.normalize_email(email)
        user = self.model(email=email, name=name, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, name, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_email_verified", True)
        return self.create_user(email, name, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    class Role(models.TextChoices):
        USER = "user", "User"
        LOCAL = "local", "Local"

    name = models.CharField(max_length=100)
    username = models.CharField(max_length=50, unique=True, blank=True)
    email = models.EmailField(unique=True)
    nomortelepon = models.CharField(max_length=20, blank=True)
    role = models.CharField(max_length=10, choices=Role.choices, default=Role.USER)
    is_email_verified = models.BooleanField(default=False)

    # Address — used to restrict locals to their own province
    negara = models.CharField(max_length=50, blank=True)
    provinsi = models.CharField(max_length=50, blank=True)
    kota = models.CharField(max_length=50, blank=True)
    kecamatan = models.CharField(max_length=50, blank=True)
    kelurahan = models.CharField(max_length=50, blank=True)

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(auto_now_add=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["name"]

    objects = UserManager()

    def __str__(self):
        return f"{self.name} ({self.email})"

    @property
    def is_local(self):
        return self.role == self.Role.LOCAL


class EmailVerification(models.Model):
    class Purpose(models.TextChoices):
        VERIFY_EMAIL = "verify_email", "Verify Email"
        RESET_PASSWORD = "reset_password", "Reset Password"

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="verifications")
    code = models.CharField(max_length=6)
    purpose = models.CharField(max_length=20, choices=Purpose.choices, default=Purpose.VERIFY_EMAIL)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)

    class Meta:
        ordering = ["-created_at"]

    def save(self, *args, **kwargs):
        if not self.pk:
            self.expires_at = timezone.now() + timezone.timedelta(minutes=OTP_EXPIRY_MINUTES)
        super().save(*args, **kwargs)

    @staticmethod
    def generate_code():
        return f"{random.randint(0, 999999):06d}"

    def is_valid(self):
        return not self.is_used and timezone.now() < self.expires_at

    def verify(self, code):
        if self.is_valid() and self.code == code:
            self.is_used = True
            self.save(update_fields=["is_used"])
            if self.purpose == self.Purpose.VERIFY_EMAIL:
                self.user.is_email_verified = True
                self.user.save(update_fields=["is_email_verified"])
            return True
        return False

    def __str__(self):
        return f"OTP({self.purpose}) for {self.user.email} ({'used' if self.is_used else 'active'})"


class PasswordResetToken(models.Model):
    """
    Short-lived token issued after a valid OTP is submitted.
    The app holds this token and presents it when setting the new password.
    """
    token = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="reset_tokens")
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)

    def save(self, *args, **kwargs):
        if not self.pk:
            self.expires_at = timezone.now() + timezone.timedelta(minutes=RESET_TOKEN_EXPIRY_MINUTES)
        super().save(*args, **kwargs)

    def is_valid(self):
        return not self.is_used and timezone.now() < self.expires_at

    def __str__(self):
        return f"ResetToken for {self.user.email} ({'used' if self.is_used else 'active'})"


class PendingEmailVerification(models.Model):
    """
    Temporary OTP store for pre-registration email verification.
    No User FK — the record is deleted or marked used once registration completes.
    """
    email = models.EmailField(db_index=True)
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)

    class Meta:
        ordering = ["-created_at"]

    def save(self, *args, **kwargs):
        if not self.pk:
            self.expires_at = timezone.now() + timezone.timedelta(minutes=OTP_EXPIRY_MINUTES)
        super().save(*args, **kwargs)

    def is_valid(self):
        return not self.is_used and timezone.now() < self.expires_at

    def verify(self, code):
        if self.is_valid() and self.code == code:
            self.is_used = True
            self.is_verified = True
            self.save(update_fields=["is_used", "is_verified"])
            return True
        return False

    def __str__(self):
        return f"PendingOTP for {self.email} ({'verified' if self.is_verified else 'used' if self.is_used else 'active'})"
