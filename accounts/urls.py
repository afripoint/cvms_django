from django.urls import path
from .views import (
    ChangePasswordAPIView,
    CreateUserAPIView,
    DeactivateUerPAIView,
    Enable2FAAPIView,
    ForgetPasswordAPIView,
    LogoutAPIView,
    PasswordTokenCheck,
    ResetPasswordAPIView,
    SetNewPasswordAPIView,
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
    path(
        "reset-password/",
        ResetPasswordAPIView.as_view(),
        name="reset-password",
    ),
    path(
        "forget-password-email/",
        ForgetPasswordAPIView.as_view(),
        name="forget-password-email",
    ),
    path(
        "reset-password-token-check/<str:uidb64>/<str:token>/",
        PasswordTokenCheck.as_view(),
        name="reset-password-token-check",
    ),
    path(
        "set-password-complete/",
        SetNewPasswordAPIView.as_view(),
        name="set-password-complete",
    ),
    path("logout/", LogoutAPIView.as_view(), name="logout"),
    # deactivated an a user
    path(
        "deactivate-admin-user/<str:slug>/",
        DeactivateUerPAIView.as_view(),
        name="deactivate-admin-user",
    ),
]
