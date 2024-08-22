from django.urls import path
from .views import AllLogAPIView


urlpatterns = [
    path("all-logs/", AllLogAPIView.as_view(), name="all logs"),
]
