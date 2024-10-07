from rest_framework import serializers

from roles.models import Role
from .models import Permission


class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = (
            "name",
            "permission_code",
            "created_at",
        )


class RoleSerializer(serializers.ModelSerializer):
    permissions = PermissionSerializer(many=True)

    class Meta:
        model = Role
        fields = ["role", "permissions"]


class RolePermissionUpdateSerializer(serializers.Serializer):
    slug = serializers.CharField(required=True)
    permissions = serializers.ListField(
        child=serializers.CharField(max_length=150), required=True
    )