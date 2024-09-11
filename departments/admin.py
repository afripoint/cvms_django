from django.contrib import admin
from .models import Rank, Command, Department, Zone


@admin.register(Department)
class LogAdmin(admin.ModelAdmin):
    list_display = (
        "department_name",
        "created",
        "updated",
    )
    list_display_links = ("department_name",)
    list_filter = (
        "department_name",
        "created",
    )
    search_fields = (
        "department_name",
        "created",
    )


@admin.register(Command)
class LogAdmin(admin.ModelAdmin):
    list_display = (
        "command_name",
        "created",
        "updated",
    )
    list_display_links = ("command_name",)
    list_filter = (
        "command_name",
        "created",
    )
    search_fields = (
        "command_name",
        "created",
    )


@admin.register(Rank)
class LogAdmin(admin.ModelAdmin):
    list_display = (
        "rank_level",
        "created",
        "updated",
    )
    list_display_links = ("rank_level",)
    list_filter = (
        "rank_level",
        "created",
    )
    search_fields = (
        "rank_level",
        "created",
    )
@admin.register(Zone)
class LogAdmin(admin.ModelAdmin):
    list_display = (
        "zone",
        "created",
        "updated",
    )
    list_display_links = ("zone",)
    list_filter = (
        "zone",
        "created",
    )
    search_fields = (
        "zone",
        "created",
    )
