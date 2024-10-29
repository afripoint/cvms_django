from django.contrib import admin

from tracker.models import Consignment


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
        "created_at",
        "updated_at",
    )
    list_display_links = (
        "bill_of_ladding",
    )
