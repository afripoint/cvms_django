from rest_framework import serializers
from .models import Command, Department, Rank, Zone
from roles.models import Role


class RoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Role
        fields = ("role",)


class RankSerializer(serializers.ModelSerializer):
    class Meta:
        model = Rank
        fields = ("rank_level",)


class ZoneSerializer(serializers.ModelSerializer):
    class Meta:
        model = Zone
        fields = ("zone",)


class DepartmentsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Department
        fields = ("department_name",)


class CommandSerializer(serializers.ModelSerializer):
    class Meta:
        model = Command
        fields = ("command_name",)


class CombinedSerializer(serializers.Serializer):
    role = RoleSerializer(many=True)
    department = DepartmentsSerializer(many=True)
    command = CommandSerializer(many=True)
    zone = ZoneSerializer(many=True)
    rank = RankSerializer(many=True)
