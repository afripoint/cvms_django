from django.contrib import admin
from .models import Permission


class PermissionsAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "created_at",
        "updated_at",
    )
    list_display_links = ("name",)


admin.site.register(Permission, PermissionsAdmin)
