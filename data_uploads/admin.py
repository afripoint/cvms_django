from django.contrib import admin
from .models import CustomDutyFile, CustomDutyFileUploads, FileActivityLog


@admin.register(CustomDutyFile)
class CustumDutyFilesAdmin(admin.ModelAdmin):
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


@admin.register(CustomDutyFileUploads)
class CustomDutyUploadsAdmin(admin.ModelAdmin):
    list_display = (
        "user",
        "uploaded_by",
        "file_name",
        "file",
        "file_type",
        "processed_status",
        "uploaded_at",
    )
    list_display_links = ("uploaded_by",)


@admin.register(FileActivityLog)
class FileActivityLogAdmin(admin.ModelAdmin):
    list_display = (
        "uploaded_by",
        "file_name",
        "file_url",
        "file_type",
        "file_size",
        "action_type",
        "ip_address",
        "user_agent",
        "uploaded_at",
    )
    list_display_links = ("file_name",)

    # Disable add, change, and delete permissions
    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
