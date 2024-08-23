from django.contrib import admin

from logs.models import Log, AuditLog

@admin.register(Log)
class LogAdmin(admin.ModelAdmin):
    list_display = ('log_type', 'timestamp', 'user', 'message', 'ip_address')
    list_filter = ('log_type', 'timestamp')
    search_fields = ('message', 'user__email')

@admin.register(AuditLog)
class LogAdmin(admin.ModelAdmin):
    list_display = ('log_type', 'timestamp', 'user', 'message', 'ip_address')
    list_filter = ('log_type', 'timestamp')
    search_fields = ('message', 'user__email')
