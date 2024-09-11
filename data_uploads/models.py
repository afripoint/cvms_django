from django.db import models


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
    
