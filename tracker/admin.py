from django.contrib import admin

from tracker.models import Consignment, TrackingRecord


@admin.register(Consignment)
class ProfileAdmin(admin.ModelAdmin):
    list_display = (
        "bill_of_ladding",
        "importer_phone",
        "registration_officer",
        "shipping_company",
        "consignee",
        "shipper",
        "terminal",
        "bonded_terminal",
        "tracking_id",
        "created_at",
        "updated_at",
    )
    list_display_links = (
        "bill_of_ladding",
        "tracking_id",
    )


@admin.register(TrackingRecord)
class ProfileAdmin(admin.ModelAdmin):
    list_display = (
        "created_by",
        "updated_by",
        "tracking_status",
        "slug",
        "created_at",
        "updated",
    )
    list_display_links = ("created_by",)
