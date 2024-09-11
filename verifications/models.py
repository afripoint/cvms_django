from django.db import models

class PaymentVerification(models.Model):
    vin = models.CharField(max_length=50, blank=False, null=True)
    cert_num = models.CharField(max_length=50, blank=False, null=True)
    email = models.CharField(max_length=50, blank=False, null=True)
    make_model = models.CharField(max_length=50, blank=False, null=True)
    year = models.CharField(max_length=50, blank=False, null=True)

    def __str__(self):
        return self.cert_num


