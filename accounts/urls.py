from django.urls import path
from .views import (
    ChangePasswordAPIView,
    CreateUserAPIView,
    Enable2FAAPIView,
    TwoFALoginAPIView,
    Verify2FAAPIView,
    VerifyUser,
    LoginAPIView,
)


urlpatterns = [
    path("create-sub-admin/", CreateUserAPIView.as_view(), name="create-sub-admin"),
    path(
        "verify-account/<str:uidb64>/<str:token>/",
        VerifyUser.as_view(),
        name="verify-account",
    ),
    path("change-password/", ChangePasswordAPIView.as_view(), name="change-password"),
    path("login/", LoginAPIView.as_view(), name="login"),
    path("two-factor-login/", TwoFALoginAPIView.as_view(), name="two-factor-login"),
    path("enable2FA/", Enable2FAAPIView.as_view(), name="enable-2FA"),
    path("verify2FA/", Verify2FAAPIView.as_view(), name="verify-2FA"),
]
