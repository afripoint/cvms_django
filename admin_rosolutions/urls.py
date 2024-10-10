from django.urls import path

from admin_rosolutions.views import VerificationReportAPIView


urlpatterns = [
    path("reports/", VerificationReportAPIView.as_view(), name='all-reports')
]
