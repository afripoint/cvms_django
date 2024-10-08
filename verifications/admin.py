from django.contrib import admin
from .models import Report, Verification


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
        "created_at",
    )


class ReportAdmin(admin.ModelAdmin):
    list_display = (
        "user",
        "user_vin",
        "query_type",
        "created_at",
    )


admin.site.register(Verification, VerificationAdmin)
admin.site.register(Report, ReportAdmin)
