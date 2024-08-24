from django.contrib import admin

from logs.models import Log, AuditLog

@admin.register(Log)
class LogAdmin(admin.ModelAdmin):
    list_display = ('log_type', 'timestamp', 'user', 'message', 'ip_address')
    list_filter = ('log_type', 'timestamp')
    search_fields = ('message', 'user__email')

    # Make all fields read-only
    readonly_fields = ('log_type', 'timestamp', 'user', 'message', 'ip_address')

     # Disable add, change, and delete permissions
    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ('log_type', 'timestamp', 'user', 'message', 'ip_address')
    list_filter = ('log_type', 'timestamp')
    search_fields = ('message', 'user__email')

    # Make all fields read-only
    readonly_fields = ('log_type', 'timestamp', 'user', 'message', 'ip_address')

     # Disable add, change, and delete permissions
    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

