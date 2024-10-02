from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from accounts.models import (
    ActivationToken,
    CVMSAuthLog,
    CustomUser,
    JWTExpirationLog,
    PasswordResetToken,
    Profile,
)


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


@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = (
        "user",
        "staff_id",
        "command",
        "created_at",
        "updated_at",
    )
    list_display_links = ("user", "staff_id",)


@admin.register(CVMSAuthLog)
class CVMSLogAdmin(admin.ModelAdmin):
    list_display = (
        "user",
        "event_type",
        "timestamp",
        "ip_address",
        "created_at",
    )
    search_fields = (
        "user__email_address",
        "event_type",
        "ip_address",
        "timestamp",
    )


@admin.register(ActivationToken)
class ActivationTokenAdmin(admin.ModelAdmin):
    list_display = (
        "user",
        "token",
        "used",
        "created_at",
    )
    search_fields = (
        "user",
        "token",
    )


@admin.register(JWTExpirationLog)
class JWTExpirationLogAdmin(admin.ModelAdmin):
    list_display = (
        "user",
        "expiration_time",
        "log_time",
        "ip_address",
        "token",
    )
    search_fields = ("ip_address",)


admin.site.register(CustomUser, CustomUserAmin)
admin.site.register(PasswordResetToken)
