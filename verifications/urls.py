from django.urls import path

from verifications.views import VerifyCertificateWithQRCodeAPIView

urlpatterns = [
    # Define the route for validating the certificate by VIN number
    path('verify-certificate/', VerifyCertificateWithQRCodeAPIView.as_view(), name='validate-certificate'),
]
