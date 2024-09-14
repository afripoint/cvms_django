from django.urls import path

from departments.views import GetALLForeignKeysAPIView


urlpatterns = [
    path(
        "",
        GetALLForeignKeysAPIView.as_view(),
        name="all-foreign-objects",
    ),
]
