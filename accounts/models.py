from django.db import models
from typing import Iterable
import secrets
import string
from django.conf import settings
from django.utils.text import slugify
from datetime import timedelta
from django.utils import timezone
import uuid
from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin,
)
import pyotp
from roles.models import Role


class MyUserManager(BaseUserManager):
    def create_user(self, email_address, password, **extra_fields):
        """
        Creates and saves a User with the given phone_number, password, and any extra fields.
        """

        if not email_address:
            raise ValueError("The Email address is required")

        email_address = self.normalize_email(email_address)

        user = self.model(email_address=email_address, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email_address, password, **extra_fields):
        """
        Creates and saves a superuser with the given phone_number, password, and any extra fields.
        """
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)
        extra_fields.setdefault("is_verified", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")
        if extra_fields.get("is_active") is not True:
            raise ValueError("Superuser must have is_active=True.")
        if extra_fields.get("is_verified") is not True:
            raise ValueError("Superuser must have is_verified=True.")

        return self.create_user(email_address, password, **extra_fields)


class CustomUser(AbstractBaseUser, PermissionsMixin):
    GENDER_CHOICES_LIST = (
        ("male", "male"),
        ("female", "female"),
    )
    REQUEST_STATUS = {
        ("approved", "approved"),
        ("declined", "declined"),
        ("pending", "pending"),
    }

    MESSAGE_CHOICES = (
        ("sms", "sms"),
        ("email", "email"),
        ("whatsapp", "whatsapp"),
    )

    phone_number = models.CharField(max_length=15, unique=True)
    first_name = models.CharField(max_length=255)
    default_password = models.CharField(max_length=50, blank=True, null=True)
    last_name = models.CharField(max_length=255)
    message_choice = models.CharField(
        max_length=50, choices=MESSAGE_CHOICES, default="sms"
    )
    email_address = models.EmailField(max_length=254, unique=True)
    login_attempts = models.IntegerField(default=0)
    last_login_attempt = models.DateTimeField(null=True, blank=True)
    gender = models.CharField(choices=GENDER_CHOICES_LIST, max_length=15)
    request_status = models.CharField(
        max_length=50, choices=REQUEST_STATUS, default="pending"
    )
    totp_secret = models.CharField(max_length=32, blank=True, null=True)
    is_2fa_enabled = models.BooleanField(default=False)
    role = models.ForeignKey(Role, on_delete=models.SET_NULL, null=True, blank=True)
    slug = models.CharField(max_length=400, blank=True, null=True, unique=True)
    otp = models.CharField(max_length=6, null=True, blank=True)
    otp_expire = models.DateTimeField(blank=True, null=True)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = "email_address"

    objects = MyUserManager()

    def __str__(self):
        return self.email_address

    class Meta:
        verbose_name = "user"
        verbose_name_plural = "users"
        # ordering = ["-first_name"]

    def unsuccessful_login_attempt(self):
        """
        Records an unsuccessful login attempt and updates the last login attempt timestamp.
        """
        self.login_attempts += 1
        self.last_login_attempt = timezone.now()
        if self.login_attempts >= 3:
            self.is_active = False
        self.save()

    def successful_login_attempt(self):
        """
        Resets the login attempts and timestamp after a successful login.
        """
        self.login_attempts = 0
        self.last_login_attempt = None
        self.save()

    def generate_totp_secret(self):
        self.totp_secret = pyotp.random_base32()
        self.save()

    def verify_totp(self, token):
        if not self.totp_secret:
            return False
        totp = pyotp.TOTP(self.totp_secret)
        return totp.verify(token)

    # Checking if the user has a specific permission
    def has_permission(self, permission_code):
        """
        Check if the user has a specific permission based on their assigned role.
        """
        if self.role:
            # Check if the role has the specific permission
            return self.role.permissions.filter(
                permission_code=permission_code
            ).exists()
        return False

    # Generate a secure random password
    @staticmethod
    def generate_default_password(length=12):
        # Generate a secure random password
        characters = string.ascii_letters + string.digits + string.punctuation
        return "".join(secrets.choice(characters) for _ in range(length))

    # send ninty days email
    def send_ninety_day_email(self):
        # Logic to send email
        pass

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.phone_number) + str(uuid.uuid4())

        # Generate a default password if not already set
        if not self.default_password:
            self.default_password = self.generate_default_password()

        if self.created_at and (timezone.now() - self.created_at) >= timedelta(days=90):
            # send an email to the user
            self.send_ninety_day_email()
            pass
        super().save(*args, **kwargs)

    def has_permission(self, permission_code):
        """
        Check if the user has a specific permission code based on their role's permissions.
        """
        if self.role:
            # Check if the user's role has the required permission
            return self.role.permissions.filter(
                permission_code=permission_code
            ).exists()
        return False


# activation token
class ActivationToken(models.Model):
    user = models.ForeignKey(
        CustomUser, related_name="activation_token", on_delete=models.CASCADE
    )
    token = models.CharField(max_length=555, unique=True, blank=True, null=True)
    used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    used_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.email_address} used the token"


class PasswordResetToken(models.Model):
    user = models.ForeignKey(
        CustomUser, related_name="reset_token", on_delete=models.CASCADE
    )
    token = models.CharField(max_length=555, unique=True, blank=True, null=True)
    used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    expired_at = models.DateTimeField()

    def is_expired(self):
        return self.expired_at < timezone.now()


class Profile(models.Model):
    user = models.OneToOneField(
        CustomUser, related_name="profile", on_delete=models.CASCADE
    )
    rank = models.CharField(max_length=50)
    staff_id = models.CharField(max_length=50)
    command = models.CharField(max_length=50)
    department = models.CharField(max_length=50)
    zone = models.CharField(max_length=50)
    slug = models.CharField(max_length=300, unique=True, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = str(uuid.uuid4())
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.user.first_name} {self.user.last_name}"


# Authentication logging
class CVMSAuthLog(models.Model):
    EVENT_TYPE_CHOICES = (
        ("login success", "Login Success"),
        ("failed login", "Failed Login"),
        ("lock account", "Lock Account"),
        ("account locked", "Account Locked"),
        ("invalid password", "Invalid Password"),
        ("inactive user", "Inactive User"),
        ("logout", "Logout"),
        ("password updated", "Password Updated"),
        ("session timeout", "Session Timeout"),
        ("user creation", "User Creation"),
        ("user deletion", "User Deletion"),
        ("update role", "Update Role"),
        ("create role", "Create Role"),
        ("create permission", "Create Permission"),
        ("delete role", "Delete Role"),
        ("unauthorized access", "Unauthorized Access"),
        ("critical error", "Critical Error"),
        ("warning", "Warning"),
        ("downtime", "Downtime"),
    )
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    event_type = models.CharField(max_length=50, choices=EVENT_TYPE_CHOICES)
    timestamp = models.DateTimeField(auto_now=True)
    device_details = models.TextField(null=True, blank=True)
    status_code = models.IntegerField(null=True, blank=True)
    location = models.CharField(max_length=255, null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    reason = models.TextField(null=True, blank=True)
    additional_info = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.event_type} - {self.user} at {self.timestamp}"

    class Meta:
        verbose_name = "CVMSAuthLog"
        verbose_name_plural = "CVMSAuthLogs"
        ordering = ["-user"]


class JWTExpirationLog(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    expiration_time = models.DateTimeField()
    log_time = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    token = models.CharField(max_length=500)
    user_agent = models.TextField(null=True, blank=True)

    def __str__(self):
        return f"Expired token for {self.user.username} at {self.expiration_time}"
