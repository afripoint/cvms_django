from django.shortcuts import render
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from drf_yasg.utils import swagger_auto_schema

from departments.models import Command, Department, Rank, Zone
from departments.serializers import CombinedSerializer
from roles.models import Role


class GetALLForeignKeysAPIView(APIView):
    @swagger_auto_schema(
        operation_summary="Fetch data from multiple models .",
        operation_description="This endpoint retrieves data from Role, Department, Rank, Command and Zone.",
    )
    def get(self, request):
        roles = Role.objects.all()
        departments = Department.objects.all()
        zones = Zone.objects.all()
        commands = Command.objects.all()
        ranks = Rank.objects.all()

        # combie the data
        combines_data = {
            "role": roles,
            "department": departments,
            "rank": ranks,
            "command": commands,
            "zone": zones,
        }

        # serializer the data
        serializer = CombinedSerializer(combines_data)

        return Response(serializer.data, status=status.HTTP_200_OK)
