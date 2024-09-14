from rest_framework import serializers
from .models import Command, Department, Rank, Zone
from roles.models import Role


class RoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Role
        fields = '__all__'

class RankSerializer(serializers.ModelSerializer):
    class Meta:
        model = Rank
        fields = '__all__'

class ZoneSerializer(serializers.ModelSerializer):
    class Meta:
        model = Zone
        fields = '__all__'

class DepartmentsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Department
        fields = '__all__'

class CommandSerializer(serializers.ModelSerializer):
    class Meta:
        model = Command
        fields = '__all__'



class CombinedSerializer(serializers.Serializer):
    role = RoleSerializer(many=True)
    department = DepartmentsSerializer(many=True)
    command = CommandSerializer(many=True)
    zone = ZoneSerializer(many=True)
    rank = RankSerializer(many=True)

