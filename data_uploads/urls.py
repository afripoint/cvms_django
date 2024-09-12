from django.urls import path

from data_uploads.views import GetAllVinAPIView, UploadFileAPIView

urlpatterns = [
    path("", UploadFileAPIView.as_view(), name="upload-vin"),
    path("get-all-vins/", GetAllVinAPIView.as_view(), name="get-all-vins"),
]
