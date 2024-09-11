from rest_framework import serializers
from logs.models import Log


class LogSerializer(serializers.ModelSerializer):
    class Meta:
        model: Log
        fields = (
            "user",
            "log_type",
            "message",
            "timestamp",
            "additional_data",
        )
