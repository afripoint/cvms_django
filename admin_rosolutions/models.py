from django.db import models
from django.contrib.contenttypes.models import ContentType
from django.contrib.contenttypes.fields import GenericForeignKey
from django.utils import timezone
from accounts.models import CustomUser

class AdminResolutionLog(models.Model):
    ACTION_TYPE_CHOICES = (
        ("report created", "Report Created"),
        ("report updated", "Report Updated"),
        ("report deleted", "Report Deleted"),
        ("view report", "View report"),
    )

    user = models.ForeignKey(CustomUser, related_name="logs", on_delete=models.CASCADE)
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id = models.PositiveIntegerField()
    content_object = GenericForeignKey('content_type', 'object_id')
    action_type = models.CharField(max_length=50, choices=ACTION_TYPE_CHOICES)
    device = models.CharField(max_length=200, blank=True, null=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user} - {self.action_type} - {self.content_object}"

    class Meta:
        verbose_name = "Admin Resolution Log"
        verbose_name_plural = "Admin Resolution Logs"
        ordering = ["-created_at"]


