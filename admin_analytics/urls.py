from django.urls import path

from admin_analytics.views import AccountSearchRatesAPIListView

urlpatterns = [
    path('accounts-search-rates/', AccountSearchRatesAPIListView.as_view(), name='account-search'),
]
