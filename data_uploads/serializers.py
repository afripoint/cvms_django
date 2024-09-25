from rest_framework import serializers
from .models import CustomDutyFile, CustomDutyFileUploads


class CustomDutyUploadSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomDutyFile
        fields = "__all__"


class CustomDutyFileUploadsSerializer(serializers.ModelSerializer):
    user = serializers.StringRelatedField()

    class Meta:
        model = CustomDutyFileUploads
        fields = (
            "user",
            "uploaded_by",
            "file_name",
            "file",
            "file_type",
            "processed_status",
            "slug",
            "uploaded_at",
        )
