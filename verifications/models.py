from django.db import models

from accounts.models import CustomUser


class Verification(models.Model):
    user = models.ForeignKey(CustomUser, related_name="verification", on_delete=models.CASCADE)
    uuid = models.CharField(max_length=50, unique=True)
    vin = models.CharField(max_length=50, unique=True)
    name = models.CharField(max_length=50, blank=False, null=True)
    cert_num = models.CharField(max_length=50, blank=False, null=True)
    email = models.CharField(max_length=50, blank=False, null=True)
    make = models.CharField(max_length=50, blank=False, null=True)
    year = models.CharField(max_length=50, blank=False, null=True)
    is_duty_paid = models.BooleanField(blank=False, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.cert_num

    class Meta:
        verbose_name = "verification"
        verbose_name_plural = "verifications"
        ordering = ["-created_at"]


class Report(models.Model):
    QUERY_TYPE_CHOICES = (
        ("fraudulent documentation", "Fraudulent Documentation"),
        ("incorrect details", "Incorrect Details"),
        ("incomplete information", "Incomplete Information"),
        ("mismatched information", "Mismatched Information"),
        ("payment discripancy", "Payment Discrepancy"),
        ("expired certificate", "Expired Certificate"),
        ("others", "Others"),
    )

    STATUS_CHOICES = (
        ("pending", "Pending"),
        ("resolved", "Resolved"),
        ("escalated", "Escalated"),
    )

    reporting_officer = models.ForeignKey(
        CustomUser, related_name="report", on_delete=models.CASCADE
    )
    vin_slug = models.ForeignKey(Verification,  related_name="reports", on_delete=models.CASCADE)
    query_type = models.CharField(
        max_length=50, choices=QUERY_TYPE_CHOICES, default="incorrect details"
    )
    files = models.ManyToManyField('ReportFile', related_name='reports', blank=True)
    additional_info = models.TextField()
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='pending')
    resolution_comment = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.reporting_officer}"

    class Meta:
        verbose_name = "report"
        verbose_name_plural = "reports"
        ordering = ["-created_at"]



class ReportFile(models.Model):
    file = models.FileField(upload_to='reports/')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.file.name
    
    class Meta:
        verbose_name = "report file"
        verbose_name_plural = "report files"
        ordering = ["-created_at"]




