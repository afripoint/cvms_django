from django.db import models
import uuid
from django.utils.text import slugify
from accounts_mobile.send import send_message


class Consignment(models.Model):
    bill_of_ladding = models.CharField(
        max_length=150, unique=True, blank=True, null=True
    )
    registration_officer = models.CharField(max_length=150, blank=True, null=True)
    shipping_company = models.CharField(max_length=150, blank=True, null=True)
    importer_phone = models.CharField(max_length=50, blank=True, null=True)
    consignee = models.CharField(max_length=150, blank=True, null=True)
    shipper = models.CharField(max_length=150, blank=True, null=True)
    terminal = models.CharField(max_length=150, blank=True, null=True)
    bonded_terminal = models.CharField(max_length=150, blank=True, null=True)
    description_of_goods = models.TextField(blank=True, null=True)
    gross_weight = models.CharField(max_length=50, blank=True, null=True)
    eta = models.DateField(blank=True, null=True)
    vessel_voyage = models.CharField(max_length=150, blank=True, null=True)
    quantity = models.CharField(max_length=50, blank=True, null=True)
    slug = models.CharField(max_length=250, blank=True, null=True)
    charges = models.CharField(max_length=50, blank=True, null=True)
    container_id = models.CharField(max_length=50, blank=True, null=True)
    hs_code = models.CharField(max_length=250, blank=True, null=True)
    port_of_loading = models.CharField(max_length=150, blank=True, null=True)
    port_of_landing = models.CharField(max_length=150, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.consignee

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.bill_of_ladding) + str(uuid.uuid4())

        super().save(*args, **kwargs)


