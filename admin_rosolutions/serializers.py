from rest_framework import serializers
from verifications.models import Report, ReportFile


class ReportFileSerializer(serializers.ModelSerializer):
    file = serializers.SerializerMethodField()

    class Meta:
        model = ReportFile
        fields = ["id", "file"]

    def get_file(self, obj):
        request = self.context.get("request")
        return request.build_absolute_uri(obj.file.url)


class VerificationsIsuesSerializer(serializers.ModelSerializer):
    files = ReportFileSerializer(many=True, read_only=True)
    reporting_officer = serializers.SerializerMethodField(read_only=True)
    vin_slug = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = Report
        fields = (
            "reporting_officer",
            "vin_slug",
            "query_type",
            "files",
            "additional_info",
            "status",
            "resolution_comment",
            "created_at",
            "updated_at",
        )

    def get_reporting_officer(self, obj):
        return {
            "full_name": f"{obj.reporting_officer.first_name} {obj.reporting_officer.last_name}",
            "email_address": obj.reporting_officer.email_address,
            "office_id": obj.reporting_officer.profile.staff_id
        }

    def get_vin_slug(self, obj):
        # Assuming Verification model has a VIN field or other identifier
        return {
            "vin": obj.vin_slug.vin,
            "name": obj.vin_slug.name,
            "cert_num": obj.vin_slug.cert_num,
            "is_duty_paid": obj.vin_slug.is_duty_paid,
        }