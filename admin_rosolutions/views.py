from django.shortcuts import render
from django.shortcuts import render, get_object_or_404
from drf_yasg.utils import swagger_auto_schema
from django.utils.dateparse import parse_date
from django.conf import settings
from django.db.models import DateField
from django.contrib.contenttypes.models import ContentType
from rest_framework.permissions import AllowAny
from rest_framework import filters
from rest_framework import generics
from datetime import datetime
from rest_framework.views import APIView
from rest_framework.response import Response
from drf_yasg import openapi
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework import status
from django.db.models.functions import Cast
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from accounts.models import CustomUser
from admin_rosolutions.models import AdminResolutionLog
from admin_rosolutions.pagination import VerificationReportPagination
from admin_rosolutions.serializers import VerificationLogsSerializer, VerificationsIsuesSerializer, VerificationsIsuesUpdateSerializer
from verifications.models import Verification, Report


class VerificationReportAPIView(generics.ListAPIView):
    # permission_classes = [IsAuthenticated, IsAdminUser]
    # authentication_classes = [JWTAuthentication]
    queryset = Report.objects.all()
    serializer_class = VerificationsIsuesSerializer
    filter_backends = [filters.SearchFilter]
    search_fields = [
        "reporting_officer__first_name",
        "reporting_officer__email_address",
    ]
    pagination_class = VerificationReportPagination

    @swagger_auto_schema(
        operation_summary="List all verification reports with optional filters",
        operation_description="""
        This endpoint retrieves all verification reports. 
        You can filter the reports using the following query parameters:

        - **start_date**: Filters reports created on or after this date (YYYY-MM-DD).
        - **end_date**: Filters reports created on or before this date (YYYY-MM-DD).
        - **status**: Filters reports by status (pending, resolved, escalated).

        Example usage:
        ```
        GET /verification-reports/?start_date=2024-01-01&end_date=2024-03-01&status=pending
        ```
        """,
        manual_parameters=[
            openapi.Parameter(
                "start_date",
                openapi.IN_QUERY,
                description="Filter reports from this date (YYYY-MM-DD)",
                type=openapi.TYPE_STRING,
                format=openapi.FORMAT_DATE,
            ),
            openapi.Parameter(
                "end_date",
                openapi.IN_QUERY,
                description="Filter reports up to this date (YYYY-MM-DD)",
                type=openapi.TYPE_STRING,
                format=openapi.FORMAT_DATE,
            ),
            openapi.Parameter(
                "status",
                openapi.IN_QUERY,
                description="Filter reports by status (pending, resolved, escalated)",
                type=openapi.TYPE_STRING,
            ),
        ],
    )
    def get_queryset(self):
        queryset = super().get_queryset()

        # Cast created_at to a date to ignore time when filtering
        queryset = queryset.annotate(created_date=Cast("created_at", DateField()))

        # Get the start and end dates from the query parameters
        start_date = self.request.query_params.get("start_date")
        end_date = self.request.query_params.get("end_date")
        status = self.request.query_params.get("status")
        query_type = self.request.query_params.get("query_type")

        # If start_date is provided, filter the queryset from that date onwards
        if start_date:
            start_date_parsed = parse_date(start_date)
            if start_date_parsed:
                queryset = queryset.filter(created_date__gte=start_date_parsed)

        # If end_date is provided, filter the queryset up to that date
        if end_date:
            end_date_parsed = parse_date(end_date)
            if end_date_parsed:
                queryset = queryset.filter(created_date__lte=end_date_parsed)

        # Filter by request_status if provided
        if status:
            queryset = queryset.filter(status=status)


        # Filter by query_type if provided
        if query_type:
            queryset = queryset.filter(query_type=query_type)

        return queryset


class VerificationReportDetailAPIView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    @swagger_auto_schema(
        operation_summary="Retrieve a specific verification report",
        operation_description="""
        This endpoint retrieves the details of a specific verification report based on the provided slug.
        
        Example usage:
        ```
        GET /verification-reports/{slug}/
        ```
        """,
        responses={
            200: openapi.Response(
                description="Successfully retrieved the report",
                examples={
                    "application/json": {
                        "data": {
                            "id": 123,
                            "slug": "report-123",
                            "status": "pending",
                            "resolution_comment": "No resolution yet",
                            # Other fields from VerificationsIsuesSerializer
                        }
                    }
                }
            ),
            404: openapi.Response(description="Report not found"),
        }
    )
    def get(self, request, slug):
        report = get_object_or_404(Report, slug=slug)
        serializer = VerificationsIsuesSerializer(report, context={"request": request})

        response = {
            "data": serializer.data,
        }
        return Response(response, status=status.HTTP_200_OK)
    
    
class VerificationReportUpdateAPIView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    @swagger_auto_schema(
        operation_summary="Update a specific verification report",
        operation_description="""
        This endpoint allows updating specific fields (status and resolution comment) of a verification report based on the provided slug.
        
        Example usage:
        ```
        PATCH /verification-reports/{slug}/
        ```
        """,
        request_body=VerificationsIsuesUpdateSerializer,
        responses={
            200: openapi.Response(
                description="Report updated successfully",
                examples={
                    "application/json": {
                        "message": "status updated successfully",
                    }
                }
            ),
            400: openapi.Response(description="Invalid data provided"),
            404: openapi.Response(description="Report not found"),
        }
    )
    def patch(self, request, slug):
        report = get_object_or_404(Report, slug=slug)
        serializer = VerificationsIsuesUpdateSerializer(report, data=request.data, context={"request": request})
        device = request.META.get('HTTP_USER_AGENT', 'unknown device')
        ip_address = request.META.get('REMOTE_ADDR')
        
        if serializer.is_valid():
            serializer.save()

            AdminResolutionLog.objects.create(
                user=request.user,
                content_type=ContentType.objects.get_for_model(Report),
                object_id=report.id,
                action_type="report updated",
                device=device,
                ip_address=ip_address,
            )

            response = {
                "message": "status updated successfully",
            }
            return Response(data=response, status=status.HTTP_200_OK)
        return Response(serializer.error_messages, status=status.HTTP_400_BAD_REQUEST)



class VerificationLog(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    @swagger_auto_schema(
        operation_summary="Retrieve all verification logs",
        operation_description="""
        This endpoint retrieves all verification logs.

        Example usage:
        ```
        GET /verification-reports/
        ```

        ### Responses:
        - **200 OK**: A list of verification logs is returned.
        - **Example Response**:
        ```json
        {
            "message": [
                {
                    "id": 1,
                    "user": "John Doe",
                    "action_type": "view",
                    "device": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                    "ip_address": "192.168.1.1",
                    "timestamp": "2024-10-10T12:34:56Z"
                },
                {
                    "id": 2,
                    "user": "Jane Smith",
                    "action_type": "update",
                    "device": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)",
                    "ip_address": "192.168.1.2",
                    "timestamp": "2024-10-10T13:45:22Z"
                }
            ]
        }
        ```
        """,
        responses={
            200: openapi.Response(
                description="Verification logs retrieved successfully",
                examples={
                    "application/json": {
                        "message": [
                            {
                                "id": 1,
                                "user": "John Doe",
                                "action_type": "view",
                                "device": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                                "ip_address": "192.168.1.1",
                                "timestamp": "2024-10-10T12:34:56Z"
                            },
                            {
                                "id": 2,
                                "user": "Jane Smith",
                                "action_type": "update",
                                "device": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)",
                                "ip_address": "192.168.1.2",
                                "timestamp": "2024-10-10T13:45:22Z"
                            }
                        ]
                    }
                },
            ),
        },
    )
    def get(self, request):
        cert_verification_logs = AdminResolutionLog.objects.all()
        serializer = VerificationLogsSerializer(cert_verification_logs, many=True)

        response = {
            "message": serializer.data
        }
        return Response(data=response, status=status.HTTP_200_OK)


