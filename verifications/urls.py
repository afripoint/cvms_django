from django.urls import path

from verifications.views import CreateReportAPIView, VerifyCertificateWithQRCodeAPIView

urlpatterns = [
    # Define the route for validating the certificate by VIN number
    path(
        "verify-certificate/",
        VerifyCertificateWithQRCodeAPIView.as_view(),
        name="varify-certificate",
    ),
    path(
        "create-report/<uuid:slug>/",
        CreateReportAPIView.as_view(),
        name="create-report",
    ),
]
