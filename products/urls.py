from django.urls import path

from products.views import (
    ProductCreationAPIView,
    ProductListAPIView,
    ProductRemoveAPIView,
    ProductStatusAPIView,
    ProductUpdateAPIView,
)

urlpatterns = [
    path(
        "",
        ProductListAPIView.as_view(),
        name="products",
    ),
    path(
        "create/",
        ProductCreationAPIView.as_view(),
        name="create-product",
    ),
    path(
        "update/<str:product_id>/",
        ProductUpdateAPIView.as_view(),
        name="update-product",
    ),
    path(
        "remove/<str:product_id>/",
        ProductRemoveAPIView.as_view(),
        name="remove-product",
    ),
    path(
        "change_status/<str:product_id>/",
        ProductStatusAPIView.as_view(),
        name="change-status",
    ),
]
