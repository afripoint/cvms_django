from django.urls import path
from .views import ChangePasswordAPIView, CreateUserAPIView, VerifyUser, LoginAPIView


urlpatterns = [
    path("create-sub-admin/", CreateUserAPIView.as_view(), name="create-sub-admin"),
    path("verify-account/<str:uidb64>/<str:token>/", VerifyUser.as_view(), name="verify-account"),
    path("change-password/", ChangePasswordAPIView.as_view(), name="change-password"),
    path("login/", LoginAPIView.as_view(), name="login"),
]
