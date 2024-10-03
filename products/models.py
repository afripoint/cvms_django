from django.db import models
from django.utils.text import slugify
import uuid


class Product(models.Model):
    product_name = models.CharField(max_length=150)
    product_description = models.TextField()
    product_price = models.IntegerField()
    slug = models.CharField(max_length=400, blank=True, null=True, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.product_name) + str(uuid.uuid4())
        super().save(*args, **kwargs)

