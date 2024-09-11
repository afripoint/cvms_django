from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from accounts.models import CustomUser


class CustomUserAmin(BaseUserAdmin):
    list_display = (
        "first_name",
        "last_name",
        "phone_number",
        "email_address",
        "role",
        "is_verified",
        "is_active",
        "created_at",
    )
    list_display_links = ("first_name", "last_name", "email_address", "phone_number")
    list_filter = ("first_name", "last_name", "phone_number")
    search_fields = ("phone_number",)
    ordering = ("-date_joined",)
    fieldsets = ()
    ordering = ("email_address",)
    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide"),
                "fields": (
                    "phone_number",
                    "first_name",
                    "last_name",
                    "email_address",
                    "password1",
                    "password2",
                ),
            },
        ),
    )


admin.site.register(CustomUser, CustomUserAmin)
