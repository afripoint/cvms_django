from django.db import models
import uuid
from django.utils.text import slugify
from permissions.models import Permission

class Role(models.Model):
    role = models.CharField(max_length=50)
    permissions = models.ManyToManyField(Permission, blank=True)
    slug = models.CharField(max_length=400, blank=True, null=True, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.role
    
    class Meta:
        verbose_name = "role"
        verbose_name_plural = "roles"
        ordering = ["-role"]

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.role) + str(uuid.uuid4())
        super().save(*args, **kwargs)
    