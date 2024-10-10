from django.urls import path

from admin_rosolutions.views import VerificationReportAPIView, VerificationReportDetailAPIView, VerificationReportUpdateAPIView


urlpatterns = [
    path("reports/", VerificationReportAPIView.as_view(), name='all-reports'),
    path("report/<slug:slug>/", VerificationReportDetailAPIView.as_view(), name='report'),
    path("report/update/<slug:slug>/", VerificationReportUpdateAPIView.as_view(), name='report-update'),
]
