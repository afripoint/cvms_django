from django.shortcuts import render
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from drf_yasg.utils import swagger_auto_schema
from logs.models import Log
from logs.serializers import LogSerializer


class AllLogAPIView(APIView):
    @swagger_auto_schema(
        operation_summary="This is endpoint gets all logs generated",
        operation_description="This endpoint gets all logs being generated",
    )
    def get(self, request, *args, **kwargs):
        logs = Log.objects.all()
        serializer = LogSerializer(logs, many=True)
        response = {
            "All Logs": serializer.data,
        }
        return Response(data=response, status=status.HTTP_200_OK)
