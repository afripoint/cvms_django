from django.urls import path
from accounts_mobile.views import LoginMobileAPIView


urlpatterns = [
    path("login/", LoginMobileAPIView.as_view(), name="mobile-login"),
]
