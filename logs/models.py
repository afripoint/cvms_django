from django.db import models
from accounts.models import CustomUser
from django.utils import timezone


class Log(models.Model):
    ERROR = "error"
    LOGIN_ATTEMPT = "login_attempt"
    INFO = "info"
    WARNING = "warning"
    DEBUG = "debug"
    LOG_TYPE_CHOICES = (
        (ERROR, "Error"),
        (LOGIN_ATTEMPT, "Login Attempt"),
        (INFO, "Information"),
        (WARNING, "Warning"),
        (DEBUG, "Debug"),
    )

    user = models.ForeignKey(
        CustomUser, on_delete=models.SET_NULL, null=True, blank=True
    )
    email = models.CharField(max_length=20, null=True, blank=True)
    log_type = models.CharField(max_length=20, choices=LOG_TYPE_CHOICES)
    message = models.TextField()
    timestamp = models.DateTimeField(default=timezone.now)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    additional_data = models.JSONField(blank=True, null=True)

    def __str__(self):
        return f"{self.log_type} - {self.timestamp}"

    class Meta:
        verbose_name = "Log"
        verbose_name_plural = "Logs"
        ordering = ["-timestamp"]


class AuditLog(models.Model):
    LOG_TYPE_CHOICES = (
        ("password_reset", "Password_Reset"),
        ("account_creation", "Account_Creation"),
        ("account_deletion", "Account_Deletion"),
        ("change role", "Change Role"),
    )
    user = models.ForeignKey(
        CustomUser, on_delete=models.SET_NULL, null=True, blank=True
    )
    log_type = models.CharField(max_length=20, choices=LOG_TYPE_CHOICES)
    message = models.TextField()
    timestamp = models.DateTimeField(default=timezone.now)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    additional_data = models.JSONField(blank=True, null=True)

    def __str__(self):
        return f"{self.log_type} - {self.timestamp}"

    class Meta:
        verbose_name = "AuditLog"
        verbose_name_plural = "AuditLogs"
        ordering = ["-timestamp"]
