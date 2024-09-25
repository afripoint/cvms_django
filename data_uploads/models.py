from django.db import models
from django.utils.text import slugify
from accounts.models import CustomUser
import uuid


class CustomDutyFile(models.Model):
    vin = models.CharField(max_length=50, blank=True, null=True)
    brand = models.CharField(max_length=50, blank=True, null=True)
    model = models.CharField(max_length=50, blank=True, null=True)
    vehicle_year = models.CharField(max_length=50, blank=True, null=True)
    engine_type = models.CharField(max_length=50, blank=True, null=True)
    vreg = models.CharField(max_length=50, blank=True, null=True)
    vehicle_type = models.CharField(max_length=50, blank=True, null=True)
    importer_tin = models.CharField(max_length=50, blank=True, null=True)
    importer_business_name = models.CharField(max_length=500, blank=True, null=True)
    importer_address = models.CharField(max_length=500, blank=True, null=True)
    origin_country = models.CharField(max_length=50, blank=True, null=True)
    hscode = models.CharField(max_length=50, blank=True, null=True)
    sgd_num = models.CharField(max_length=50, blank=True, null=True)
    sgd_date = models.CharField(max_length=50, blank=True, null=True)
    office_cod = models.CharField(max_length=50, blank=True, null=True)
    payment_status = models.CharField(max_length=50, blank=True, null=True)

    def __str__(self):
        return f"{self.brand} with vin number: {self.vin}"
    
    class Meta:
        verbose_name = "customDutyFile"
        verbose_name_plural = "customDutyFiles"
        ordering = ["vin"]
    

class CustomDutyFileUploads(models.Model):
    uploaded_by = models.ForeignKey(CustomUser, on_delete=models.DO_NOTHING)
    file_name = models.CharField(max_length=255)
    file = models.FileField(upload_to='uploads/')
    file_type = models.CharField(max_length=10)
    processed_status = models.BooleanField(default=False)
    slug = models.CharField(max_length=400, blank=True, null=True, unique=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'{self.file_type} was uploaded recently  - {self.uploaded_at}'
    

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.file.name) + str(uuid.uuid4())

        super().save(*args, **kwargs)

    class Meta:
        verbose_name = "customDutyFileUpload"
        verbose_name_plural = "customDutyFileUploads"
        ordering = ["-uploaded_by"]
    

class FileActivityLog(models.Model):
    UPLOAD = 'upload'
    DOWNLOAD = 'download'
    ACTION_CHOICES = [
        (UPLOAD, 'Upload'),
        (DOWNLOAD, 'Download')
    ]

    uploaded_by = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, related_name="file_activities")
    file_name = models.CharField(max_length=255)
    file_url = models.URLField(max_length=500)
    file_type = models.CharField(max_length=50)
    file_size = models.BigIntegerField()
    action_type = models.CharField(max_length=10, choices=ACTION_CHOICES)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=255, null=True, blank=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = 'File Activity Log'
        verbose_name_plural = 'File Activity Logs'
        ordering = ['-uploaded_at']

    def __str__(self):
        return f"{self.uploaded_by} {self.action_type} {self.file_name} on {self.uploaded_at}"