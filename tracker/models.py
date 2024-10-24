from django.db import models
import uuid
from django.utils.text import slugify

from accounts_mobile.send import send_message


class Consignment(models.Model):
    SHIPMENT_STATUS = (
        ("in transit", "In Transit"),
        ("cleared", "Cleared"),
        ("on hold", "On Hold"),
        ("inspection completed", "Inspection Completed"),
        ("pending inspection", "Pending Inspection"),
        ("inspection hold", "Inspection Hold"),
        ("in warehouse", "In Warehouse"),
        ("pending transfer", "Pending Transfer"),
        ("warehouse exit initiated", "Warehouse Exit Initiated"),
        ("in terminal", "In Terminal"),
        ("cleared from terminal", "Cleared From Terminal"),
        ("pending terminal processing", "Pending Terminal Processing"),
    )
    bill_of_ladding = models.CharField(
        max_length=150, unique=True, blank=True, null=True
    )
    registration_officer = models.CharField(max_length=150, blank=True, null=True)
    shipping_company = models.CharField(max_length=150, blank=True, null=True)
    importer_phone = models.CharField(max_length=50, blank=True, null=True)
    consignee = models.CharField(max_length=150, blank=True, null=True)
    shipping_status = models.CharField(
        max_length=50, choices=SHIPMENT_STATUS, default="in transit"
    )
    shipper = models.CharField(max_length=150, blank=True, null=True)
    terminal = models.CharField(max_length=150, blank=True, null=True)
    bonded_terminal = models.CharField(max_length=150, blank=True, null=True)
    tracking_id = models.CharField(max_length=150, unique=True, blank=True, null=True)
    description_of_goods = models.TextField(blank=True, null=True)
    gross_weight = models.CharField(max_length=50, blank=True, null=True)
    eta = models.DateField(blank=True, null=True)
    vessel_voyage = models.CharField(max_length=150, blank=True, null=True)
    quantity = models.CharField(max_length=50, blank=True, null=True)
    slug = models.CharField(max_length=250, blank=True, null=True)
    hs_code = models.CharField(max_length=250, blank=True, null=True)
    port_of_loading = models.CharField(max_length=150, blank=True, null=True)
    port_of_landing = models.CharField(max_length=150, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.consignee

    def save(self, *args, **kwargs):
        if not self.tracking_id:
            prefix = "CUST"
            count = Consignment.objects.count() + 1
            self.tracking_id = f"{prefix}-{count:06d}"  # Example: CUST-000001

        if not self.slug:
            self.slug = slugify(self.bill_of_ladding) + str(uuid.uuid4())

        if self.bill_of_ladding is not None:
            # consignment = Consignment.objects.get(bill_of_ladding=self.bill_of_ladding)
            send_message(
                phone_number=self.importer_phone,
                message=f"Dear {self.consignee} your consignment has been recorded and your trackingID is {self.tracking_id} ",
            )

        super().save(*args, **kwargs)


class TrackingRecord(models.Model):
    TRACKING_STATUS = (
        ("tracking created", "Tracking Created"),
        ("tracking updated", "Tracking Updated"),
    )
    created_by = models.ForeignKey(
        Consignment, related_name="consignment", on_delete=models.CASCADE
    )
    updated_by = models.CharField(max_length=50, blank=True, null=True)
    tracking_status = models.CharField(max_length=50, choices=TRACKING_STATUS, default='tracking created')
    slug = models.CharField(max_length=250, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.created_by.consignee

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.created_by.bill_of_ladding) + str(uuid.uuid4())
        super().save(*args, **kwargs)


# class EntityStages(models.Model):
#     pass
