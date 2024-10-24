from django.urls import path

from tracker.views import ConsignmentRegistrationAPIView, ConsignmentUpdateAPIView

urlpatterns = [
    path(
        "create-consignment/",
        ConsignmentRegistrationAPIView.as_view(),
        name="create-consignment",
    ),
    path(
        "update-consignment/<slug:slug>/",
        ConsignmentUpdateAPIView.as_view(),
        name="update-tracker",
    ),
]
