from rest_framework import serializers
from .models import Report, ReportFile


class PaymentVerificationSerializer(serializers.Serializer):
    cert_num = serializers.CharField(max_length=255)


class ReportFileSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReportFile
        fields = ("file",)


class ReportSerializer(serializers.ModelSerializer):
    file = ReportFileSerializer(many=True, required=False)
    query_type = serializers.ChoiceField(
        choices=Report.QUERY_TYPE_CHOICES, default="incorrect details"
    )

    class Meta:
        model = Report
        fields = (
            "query_type",
            "additional_info",
            "file",
        )
