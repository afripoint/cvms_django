from django.urls import path

from plans.views import WalletPlanListAPIView, WalletSubscriptionListAPIView


urlpatterns = [
    path(
        "wallet/",
        WalletPlanListAPIView.as_view(),
        name="wallet_plans",
    ),
    path(
        "wallet-subscriptions/",
        WalletSubscriptionListAPIView.as_view(),
        name="wallet-subscription-list",
    ),
]
