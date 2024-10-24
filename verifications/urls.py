from django.urls import path

from verifications.views import CreateReportAPIView, VerificationDetailAPIView, VerificationHistoryAPIView, VerifyCertificateWithQRCodeAPIView

urlpatterns = [
    # Define the route for validating the certificate by VIN number
    path(
        "verify-certificate/",
        VerifyCertificateWithQRCodeAPIView.as_view(),
        name="varify-certificate",
    ),
    path(
        "create-report/<slug:slug>/",
        CreateReportAPIView.as_view(),
        name="create-report",
    ),
    path(
        "history/",
        VerificationHistoryAPIView.as_view(),
        name="history",
    ),
    path(
        "detail/<uuid:slug>/",
        VerificationDetailAPIView.as_view(),
        name="detail-history",
    ),
]
