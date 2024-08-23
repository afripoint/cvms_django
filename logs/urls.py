from django.urls import path
from .views import AllAuditLogAPIView, AllLogAPIView


urlpatterns = [
    path("all-logs/", AllLogAPIView.as_view(), name="all logs"),
    path("all-audit-logs/", AllAuditLogAPIView.as_view(), name="all-audit-logs"),
]
