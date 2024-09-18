from django.shortcuts import render
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from drf_yasg.utils import swagger_auto_schema
from rest_framework.response import Response
from rest_framework import status
from django.core.exceptions import ObjectDoesNotExist
from django.db import DatabaseError
from rest_framework.exceptions import ValidationError

from departments.models import Command, Department, Rank, Zone
from departments.serializers import CombinedSerializer
from roles.models import Role


class GetALLForeignKeysAPIView(APIView):
    @swagger_auto_schema(
        operation_summary="Fetch data from multiple models.",
        operation_description="This endpoint retrieves data from Role, Department, Rank, Command and Zone.",
    )
    def get(self, request):
        try:
            roles = Role.objects.all()
            departments = Department.objects.all()
            zones = Zone.objects.all()
            commands = Command.objects.all()
            ranks = Rank.objects.all()

            # Combine the data
            combines_data = {
                "role": roles,
                "department": departments,
                "rank": ranks,
                "command": commands,
                "zone": zones,
            }

            # Serialize the data
            serializer = CombinedSerializer(combines_data)
            return Response(serializer.data, status=status.HTTP_200_OK)

        except ObjectDoesNotExist:
            return Response({"error": "One or more requested objects do not exist."}, status=status.HTTP_404_NOT_FOUND)
        except DatabaseError:
            return Response({"error": "Database error occurred."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except ValidationError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": "An unexpected error occurred: " + str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)