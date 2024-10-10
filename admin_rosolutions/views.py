from django.shortcuts import render
from django.shortcuts import render, get_object_or_404
from drf_yasg.utils import swagger_auto_schema
from django.conf import settings
from django.db.models import DateField
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
from rest_framework.permissions import IsAuthenticated
from accounts.models import CustomUser
from admin_rosolutions.pagination import VerificationReportPagination
from admin_rosolutions.serializers import VerificationsIsuesDetailSerializer, VerificationsIsuesSerializer
from verifications.models import Verification, Report


class VerificationReportAPIView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]
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

        return queryset


class VerificationReportDetailAPIView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

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
    def patch(self, request, slug):
        report = get_object_or_404(Report, slug=slug)
        serializer = VerificationsIsuesDetailSerializer(report, context={"request": request})
        
        if serializer.is_valid():
            serializer.save()

            response = {
                "message": "status updated successfully",
            }
            return Response(data=response, status=status.HTTP_200_OK)
        return Response(serializer.error_messages, status=status.HTTP_400_BAD_REQUEST)





