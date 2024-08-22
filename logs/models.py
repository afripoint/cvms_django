from django.db import models
from accounts.models import CustomUser
from django.utils import timezone

class Log(models.Model):
    LOG_TYPE_CHOICES = (
        ('error', 'Error'),
        ('login_attempt', 'Login Attempt'),
        ('info', 'Information'),
        ('warning', 'Warning'),
        ('debug', 'Debug'),
    )

    user = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, blank=True)
    log_type = models.CharField(max_length=20, choices=LOG_TYPE_CHOICES)
    message = models.TextField()
    timestamp = models.DateTimeField(default=timezone.now)
    additional_data = models.JSONField(blank=True, null=True)

    def __str__(self):
        return f'{self.log_type} - {self.timestamp}'

    class Meta:
        verbose_name = 'Log'
        verbose_name_plural = 'Logs'
        ordering = ['-timestamp']

