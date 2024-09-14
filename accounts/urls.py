from django.urls import path
from .views import (
    AllUsersAPIView,
    ChangeDefaultPasswordAPIView,
    # CreateUserAPIView,
    DeactivateUerPAIView,
    Enable2FAAPIView,
    ForgetPasswordAPIView,
    GrantAccessAPIView,
    LogoutAPIView,
    PasswordTokenCheck,
    ResetPasswordAPIView,
    SetNewPasswordAPIView,
    TwoFALoginAPIView,
    UserCreationRequestAPIView,
    Verify2FAAPIView,
    VerifyUser,
    LoginAPIView,
)


urlpatterns = [
    # path("create-sub-admin/", CreateUserAPIView.as_view(), name="create-sub-admin"),
    path(
        "verify-account/<str:uidb64>/<str:token>/",
        VerifyUser.as_view(),
        name="verify-account",
    ),
    path("change-default-password/", ChangeDefaultPasswordAPIView.as_view(), name="change-default-password"),
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
        "forgot-password/",
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
    # user_creation_request
    path(
        "user-creation-request/",
        UserCreationRequestAPIView.as_view(),
        name="user-creation-request",
    ),
    # grant access by thee super user
    path(
        "grant-access/<str:slug>/",
        GrantAccessAPIView.as_view(),
        name="grant-access",
    ),
    # unverified-users
    path(
        "unverified-users/",
        AllUsersAPIView.as_view(),
        name="unverified-user",
    ),
]
