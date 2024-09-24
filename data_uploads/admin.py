from django.contrib import admin
from .models import CustomDutyFile


@admin.register(CustomDutyFile)
class LogAdmin(admin.ModelAdmin):
    list_display = (
        "vin",
        "brand",
        "model",
        "vehicle_year",
        "engine_type",
        "vreg",
        "vehicle_type",
        "importer_tin",
        "importer_business_name",
        "importer_address",
        "origin_country",
        "hscode",
        "sgd_num",
        "sgd_date",
        "office_cod",
        "payment_status",
    )

    list_display_links = (
        "vin",
        "brand",
        "model",
    )

     # Disable add, change, and delete permissions
    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    # def has_delete_permission(self, request, obj=None):
    #     return False

    # list_filter = (
    #     "vin",
    #     "brand",
    #     "model",
    # )
    # search_fields = (
    #     "vin",
    #     "brand",
    #     "model",
    # )
