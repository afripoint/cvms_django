from django.urls import path

from products.views import (
    ProductCreationAPIView,
    ProductListAPIView,
    ProductRemoveAPIView,
    ProductRetrieveAPIView,
    ProductUpdateAPIView,
)

urlpatterns = [
    path("", ProductListAPIView.as_view(), name="product-list"),
    path(
        "retrieve/<slug:slug>/",
        ProductRetrieveAPIView.as_view(),
        name="product-list",
    ),
    path(
        "create/",
        ProductCreationAPIView.as_view(),
        name="create-product",
    ),
    path(
        "update/<slug:slug>/",
        ProductUpdateAPIView.as_view(),
        name="update-product",
    ),
    path(
        "remove/<slug:slug>/",
        ProductRemoveAPIView.as_view(),
        name="remove-product",
    ),
]
