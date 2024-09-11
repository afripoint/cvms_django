from rest_framework import serializers
from .models import CustomDutyFile



class CustomDutyUploadSerializer(serializers.ModelSerializer):
    class Meta:
        model =  CustomDutyFile
        fields = ("__all__")