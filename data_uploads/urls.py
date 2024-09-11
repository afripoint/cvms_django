from django.urls import path

from data_uploads.views import UploadFileAPIView

urlpatterns = [
    path("", UploadFileAPIView.as_view(), name="upload-vin"),
]
