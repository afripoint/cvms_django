from django.urls import path
from .views import (
    AllProfileDetailAPIView,
    AllProfileView,
    AllUsersList,
    ChangeDefaultPasswordAPIView,
    DeactivateUserAPIView,
    Enable2FAAPIView,
    ForgetPasswordAPIView,
    GrantAccessAPIView,
    LogoutAPIView,
    PasswordTokenCheck,
    ResetPasswordAPIView,
    SetNewPasswordAPIView,
    TwoFALoginAPIView,
    UserCreationRequestAPIView,
    UserDetailView,
    UserProfileAPIView,
    UserProfileUpdateAPIView,
    UserProfileUpdateAdminAPIView,
    Verify2FAAPIView,
    VerifyUser,
    LoginAPIView,
)


urlpatterns = [
    # veriify an admin user and redirect to update password view
    path(
        "verify-account/<str:uidb64>/<str:token>/",
        VerifyUser.as_view(),
        name="verify-account",
    ),
    path(
        "change-default-password/",
        ChangeDefaultPasswordAPIView.as_view(),
        name="change-default-password",
    ),
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
        name="forgot-password/",
    ),
    path("logout/", LogoutAPIView.as_view(), name="logout"),
    # deactivated an a user
    path(
        "deactivate-admin-user/<str:slug>/",
        DeactivateUserAPIView.as_view(),
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
        "grant-access/<slug:slug>/",
        GrantAccessAPIView.as_view(),
        name="grant-access",
    ),
    # all-users
    path(
        "all-users/",
        AllUsersList.as_view(),
        name="all-users",
    ),
    # user-detail
    path(
        "user-details/<slug:slug>/",
        UserDetailView.as_view(),
        name="user-details",
    ),
    # users-profile
    path(
        "user-profiles/",
        AllProfileView.as_view(),
        name="users-profiles",
    ),
    # users-profile-detail - admin
    path(
        "user-profile-detail/<slug:slug>/",
        AllProfileDetailAPIView.as_view(),
        name="users-profile-detail",
    ),
    # users-profile-update - admin
    path(
        "user-profile-update/<slug:slug>/",
        UserProfileUpdateAdminAPIView.as_view(),
        name="users-profile-update",
    ),
    path(
        "logged-in-profile-view/<slug:slug>/",
        UserProfileAPIView.as_view(),
        name="logged-in-profile-view",
    ),
    path(
        "logged-in-profile-update/<slug:slug>/",
        UserProfileUpdateAPIView.as_view(),
        name="logged-in-profile-update",
    ),
]
