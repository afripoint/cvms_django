from django.db import models


class Permission(models.Model):
    name = models.CharField(max_length=255)
    permission_code = models.CharField(max_length=150)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = "Permission"
        verbose_name_plural = "Permissions"
        ordering = ["-name"]


class PermissionsLog(models.Model):
    EVENT__TYPES = (
        ("create permission", "Create Permission"),
        ("update permiission", "Update Permission"),
        ("delete permission", "Delete Permission"),
        ("create role", "Create Role"),
        ("update role", "Update Role"),
        ("delete role", "Delete Role"),
    )

    created_by  = models.ForeignKey("accounts.CustomUser", related_name='permission_log', on_delete=models.DO_NOTHING)
    event_type = models.CharField(max_length=50, choices=EVENT__TYPES)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    description = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user} {self.event_type} {self.ip_address} on {self.timestamp}"
