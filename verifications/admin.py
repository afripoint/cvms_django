from django.contrib import admin
from .models import Report, ReportFile, Verification


class VerificationAdmin(admin.ModelAdmin):
    list_display = (
        "user",
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
        "reporting_officer",
        "vin",
        "query_type",
        "created_at",
    )


class ReportFileAdmin(admin.ModelAdmin):
    list_display = (
        "file",
        "created_at",
    )


admin.site.register(Verification, VerificationAdmin)
admin.site.register(Report, ReportAdmin)
admin.site.register(ReportFile, ReportFileAdmin)
