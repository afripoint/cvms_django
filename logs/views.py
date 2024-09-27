from django.shortcuts import render
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from drf_yasg.utils import swagger_auto_schema
from accounts.models import CVMSAuthLog
from accounts.serializers import CVMSAuthLogSerializer
from logs.models import AuditLog, Log
from logs.serializers import LogSerializer

# All logs
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

    # All audit_Logs


class AllAuditLogAPIView(APIView):
    @swagger_auto_schema(
        operation_summary="This is endpoint gets all audit logs generated",
        operation_description="This endpoint gets all audit logs being generated",
    )
    def get(self, request, *args, **kwargs):
        audit_logs = AuditLog.objects.all()
        serializer = LogSerializer(audit_logs, many=True)
        response = {
            "All_Audit_Logs": serializer.data,
        }
        return Response(data=response, status=status.HTTP_200_OK)


class AuthLogAPIView(APIView):
    @swagger_auto_schema(
        operation_summary="This is endpoint gets all authentication logs generated",
        operation_description="This endpoint gets all authentication logs being generated",
    )
    def get(self, request, *args, **kwargs):
        authLog = CVMSAuthLog.objects.all()
        serializer = CVMSAuthLogSerializer(authLog, many=True)
        
        response = {
            "All_Authentication_Logs": serializer.data,
        }
        return Response(data=response, status=status.HTTP_200_OK)