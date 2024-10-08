from rest_framework import serializers
from .models import Report, ReportFile


class PaymentVerificationSerializer(serializers.Serializer):
    cert_num = serializers.CharField(max_length=255)


class ReportFileSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReportFile
        fields = ("file",)


class ReportSerializer(serializers.ModelSerializer):
    user = serializers.SerializerMethodField(read_only=True)
    user_vin = serializers.SerializerMethodField(read_only=True)
    file = ReportFileSerializer(many=True, required=False)
    query_type = serializers.ChoiceField(
        choices=Report.QUERY_TYPE_CHOICES, default="incorrect details"
    )

    class Meta:
        model = Report
        fields = (
            "user",
            "user_vin",
            "query_type",
            "additional_info",
            "file",
            "status",
            "created_at",
            "updated_at",
        )
        read_only_fields = (
            "user",
            "user_vin",
            "status",
            "created_at",
            "updated_at",
        )

    def get_user(self, obj):
        return obj.user.profile.staff_id

