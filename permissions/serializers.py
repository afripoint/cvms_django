from rest_framework import serializers

from roles.models import Role
from .models import Permission, PermissionsLog


class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = (
            "name",
            "permission_code",
        )


class RolesSerializer(serializers.ModelSerializer):
    permissions = serializers.SlugRelatedField(
        slug_field="permission_code",  # or 'name' depending on your preference
        queryset=Permission.objects.all(),
        many=True,
        write_only=True,
    )

    class Meta:
        model = Role
        fields = [
            "role",
            "permissions",  # Write-only field for POST/PUT requests
            "slug",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ("slug", "created_at", "updated_at")


class RolesWithPermissionsSerializer(serializers.ModelSerializer):
    permissions = PermissionSerializer(many=True, read_only=True)

    class Meta:
        model = Role
        fields = [
            "role",
            "permissions",  # Read-only field for GET requests
            "slug",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ("slug", "created_at", "updated_at")


class PermissionLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = PermissionsLog
        fields = (
            "created_by",
            "event_type",
            "ip_address",
            "description",
            "timestamp",
        )
