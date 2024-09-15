from typing import Iterable
import secrets
import string
from django.db import models
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

from departments.models import Command, Department, Rank, Zone
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
    # ROLE_CHOICES_LIST = (
    #     ("support_level1", "support_level1"),
    #     ("support_level2", "support_level2"),
    #     ("support_level3", "support_level3"),
    #     ("accountant1", "accountant1"),
    #     ("accountant2", "accountant2"),
    #     ("accountant3", "accountant3"),
    #     ("compliance", "compliance"),
    #     ("content_creator", "content_creator"),
    # )
    phone_number = models.CharField(max_length=15, unique=True)
    first_name = models.CharField(max_length=255)
    default_password = models.CharField(max_length=50, blank=True, null=True)
    last_name = models.CharField(max_length=255)
    email_address = models.EmailField(max_length=254, unique=True)
    login_attempts = models.IntegerField(default=0)
    last_login_attempt = models.DateTimeField(null=True, blank=True)
    gender = models.CharField(choices=GENDER_CHOICES_LIST, max_length=15)
    request_status = models.CharField(
        max_length=50, choices=REQUEST_STATUS, default="pending"
    )
    totp_secret = models.CharField(max_length=32, blank=True, null=True)
    is_2fa_enabled = models.BooleanField(default=False)
    role = models.ForeignKey(Role, on_delete=models.CASCADE, blank=True, null=True)
    slug = models.CharField(max_length=400, blank=True, null=True, unique=True)
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
        ordering = ["-email_address"]

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


# activation token
class ActivationToken(models.Model):
    user = models.ForeignKey(
        CustomUser, related_name="activation_token", on_delete=models.CASCADE
    )
    token = models.CharField(max_length=555, unique=True)
    used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.email_address} used the token"


class support_level1_profile(models.Model):
    user = models.ForeignKey(
        CustomUser, related_name="support_level1_profiles", on_delete=models.CASCADE
    )
    rank = models.ForeignKey(Rank, on_delete=models.CASCADE)
    staff_id = models.CharField(max_length=50)
    command = models.ForeignKey(Command, on_delete=models.CASCADE)
    department = models.ForeignKey(Department, on_delete=models.CASCADE)
    zone = models.ForeignKey(Zone, on_delete=models.CASCADE)
    slug = models.CharField(max_length=300, unique=True, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = str(uuid.uuid4())
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.user.first_name} {self.user.last_name}"
