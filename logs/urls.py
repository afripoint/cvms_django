from django.urls import path
from .views import AllLogsAPIView


urlpatterns = [
    path("all-logs/", AllLogsAPIView.as_view(), name="all-auth-logs"),
]
