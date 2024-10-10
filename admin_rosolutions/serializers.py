from rest_framework import serializers
from verifications.models import Report, ReportFile
from django.core.validators import MaxLengthValidator


class ReportFileSerializer(serializers.ModelSerializer):
    file = serializers.SerializerMethodField()

    class Meta:
        model = ReportFile
        fields = ["id", "file"]

    def get_file(self, obj):
        request = self.context.get("request")
        if request is not None:
            return request.build_absolute_uri(obj.file.url)
        return obj.file.url


class VerificationsIsuesSerializer(serializers.ModelSerializer):
    files = ReportFileSerializer(many=True, read_only=True)
    reporting_officer = serializers.SerializerMethodField(read_only=True)
    vin = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = Report
        fields = (
            "reporting_officer",
            "vin",
            "query_type",
            "files",
            "slug",
            "additional_info",
            "status",
            "created_at",
            "updated_at",
        )

    def get_reporting_officer(self, obj):
        return {
            "full_name": f"{obj.reporting_officer.first_name} {obj.reporting_officer.last_name}",
            "email_address": obj.reporting_officer.email_address,
            "office_id": obj.reporting_officer.profile.staff_id,
        }

    def get_vin(self, obj):
        # Assuming Verification model has a VIN field or other identifier
        return {
            "vin": obj.vin.vin,
            "name": obj.vin.name,
            "cert_num": obj.vin.cert_num,
            "is_duty_paid": obj.vin.is_duty_paid,
        }


class VerificationsIsuesDetailSerializer(serializers.ModelSerializer):
    resolution_comment = serializers.CharField(
        max_length=500,
        validators=[MaxLengthValidator(500)],
        error_messages={
            "max_length": "The resolution comment must not exceed 500 characters."
        },
    )
    status = serializers.ChoiceField(
        choices=Report.STATUS_CHOICES, default="pending"
    )

    class Meta:
        model = Report
        fields = ("resolution_comment", "status")

    def validate_resolution_comment(self, value):
        """
        Additional validation for resolution_comment, if needed.
        """
        if len(value) > 500:
            raise serializers.ValidationError(
                "Resolution comment cannot be longer than 500 characters."
            )
        return value
