from rest_framework import serializers
from .models import Report, ReportFile, Verification


class ReportFileSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReportFile
        fields = ("file",)


class ReportSerializer(serializers.ModelSerializer):
    files = ReportFileSerializer(many=True, required=False)
    reporting_officer = serializers.SerializerMethodField(read_only=True)
    vin = serializers.SerializerMethodField(read_only=True)
    query_type = serializers.ChoiceField(
        choices=Report.QUERY_TYPE_CHOICES, default="incorrect details"
    )

    class Meta:
        model = Report
        fields = (
            "query_type",
            "additional_info",
            "files",
            "vin",
            "reporting_officer",
        )
        read_only_fields = ("reporting_officer", "vin")

    def get_reporting_officer(self, obj):
        return {
            "full_name": f"{obj.reporting_officer.first_name} {obj.reporting_officer.last_name}",
            "email_address": obj.reporting_officer.email_address,
            "staff_id": obj.reporting_officer.profile.staff_id if hasattr(obj.reporting_officer.profile, 'staff_id') else None,
        }

    def get_vin(self, obj):
        # Assuming Verification model has a VIN field or other identifier
        return {
            "vin": obj.vin.vin,
            "name": obj.vin.name,
            "cert_num": obj.vin.cert_num,
            "is_duty_paid": obj.vin.is_duty_paid,
        }

    def create(self, validated_data):
        # files_data = validated_data.pop('files', [])
        files_data = self.context["request"].FILES.getlist("files")
        reporting_officer = self.context["request"].user
        vin = self.context["vin"]

        report = Report.objects.create(
            reporting_officer=reporting_officer,
            vin=vin,
            query_type=validated_data["query_type"],
            additional_info=validated_data["additional_info"],
        )

        # Create associated ReportFiles
        for file in files_data:
            report_file = ReportFile.objects.create(file=file)
            report.files.add(report_file)

        return report


class VerificationHistorySerializer(serializers.ModelSerializer):
    user = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = Verification
        fields = (
            "user",
            "uuid",
            "vin",
            "name",
            "cert_num",
            "email",
            "make",
            "year",
            "is_duty_paid",
            "created_at",
        )

    def get_user(self, obj):
        return f"{obj.user.first_name} {obj.user.last_name}"
