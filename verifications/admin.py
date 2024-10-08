from django.contrib import admin
from .models import Verification


class VerificationAdmin(admin.ModelAdmin):
    list_display = (
        "uuid",
        "vin",
        "name",
        "cert_num",
        "email",
        "make",
        "year",
        "is_duty_paid",
        # "created_at",
    )


admin.site.register(Verification, VerificationAdmin)
