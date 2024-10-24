from django.urls import path

from admin_analytics.views import (
    AccountSearchRatesAPIListView,
    AccountsDistributionAPIListView,
    RegistrationAPIListView,
    SignUpSearchComparisonAPIListView,
    TopAccountsAPIListView,
    VinSearchGrowthAPIListView,
)

urlpatterns = [
    path(
        "accounts-search-rates/",
        AccountSearchRatesAPIListView.as_view(),
        name="account-search",
    ),
    path(
        "signup-search-comparison/",
        SignUpSearchComparisonAPIListView.as_view(),
        name="signup-search",
    ),
    path("vin-search-growth/", VinSearchGrowthAPIListView.as_view(), name="vin-search"),
    path("registrations/", RegistrationAPIListView.as_view(), name="registration"),
    path("top-accounts/", TopAccountsAPIListView.as_view(), name="top-accounts"),
    path(
        "accounts-distribution/",
        AccountsDistributionAPIListView.as_view(),
        name="accounts-distribution",
    ),
]
