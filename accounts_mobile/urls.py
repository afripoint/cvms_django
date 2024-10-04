from django.urls import path
from accounts_mobile.views import ForgetPasswordAPIView, LoginMobileAPIView, OTPVerificationView


urlpatterns = [
    path("login/", LoginMobileAPIView.as_view(), name="mobile-login"),
    path("forget_password/", ForgetPasswordAPIView.as_view(), name="forget-password-request-email-mobile"),
    path("verify/<slug:slug>/", OTPVerificationView.as_view(), name="verify-mobile"),
]