from rest_framework import serializers
from .models import Report, ReportFile, Verification


class ReportFileSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReportFile
        fields = ("file",)


class ReportSerializer(serializers.ModelSerializer):
    files = ReportFileSerializer(many=True, required=False)
    user = serializers.SerializerMethodField(read_only=True)
    vin_slug = serializers.SerializerMethodField(read_only=True)
    query_type = serializers.ChoiceField(
        choices=Report.QUERY_TYPE_CHOICES, default="incorrect details"
    )

    class Meta:
        model = Report
        fields = ("query_type", "additional_info", "files", "vin_slug", "user")
        read_only_fields = ("user", "vin_slug")

    def get_user(self, obj):
        return obj.user.profile.staff_id

    def create(self, validated_data):
        # files_data = validated_data.pop('files', [])
        files_data = self.context["request"].FILES.getlist("files")
        user = self.context["request"].user
        vin_slug = self.context["vin_slug"]

        report = Report.objects.create(
            user=user,
            vin_slug=vin_slug,
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
        return obj.user.profile.staff_id
