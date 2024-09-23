from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.core.files.storage import FileSystemStorage
from rest_framework.generics import GenericAPIView
import csv
from rest_framework import generics
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from data_uploads.pagination import VinPagination
from data_uploads.utils import (
    is_duplicate,
    process_csv,
    process_excel,
    process_json,
    process_xml,
)
from .serializers import CustomDutyUploadSerializer
from .models import CustomDutyFile
from rest_framework.response import Response
from drf_yasg.utils import swagger_auto_schema
import pandas as pd
from drf_yasg import openapi


class UploadFileAPIView(APIView):
    MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

    @swagger_auto_schema(
        operation_summary="Upload a file and process custom duty payment.",
        operation_description="""
            This endpoint allows you to upload a file (CSV, Excel, JSON, or XML) 
            and updates the custom duty payment based on the content of the file.
            Supported formats: CSV, Excel (.xls/.xlsx), JSON, XML. The file size limit is 5MB.
        """,
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "file": openapi.Schema(
                    type=openapi.TYPE_FILE,
                    description="File to upload (CSV, Excel, JSON, or XML). Max size: 5MB",
                )
            },
        ),
        responses={
            200: openapi.Response(
                description="File processed and saved successfully.",
                examples={
                    "application/json": {
                        "message": "File processed and saved successfully.",
                        "file_url": "http://example.com/uploads/yourfile.csv",
                        "result": {"processed_data": "Details about processed data"},
                    }
                },
            ),
            400: openapi.Response(
                description="Bad request, file validation failed.",
                examples={
                    "application/json": {
                        "error": "File size exceeds the maximum limit of 5MB."
                    },
                    "application/json": {"error": "No file uploaded"},
                    "application/json": {
                        "error": "Invalid file format. Please upload a CSV, Excel, JSON, or XML file."
                    },
                },
            ),
        },
    )
    # Define the maximum allowed file size (in bytes)

    def post(self, request, *args, **kwargs):
        # Check if file is in request
        file = request.FILES.get("file")
        # overwrite = request.data.get("overwrite", False)

        if not file:
            return Response(
                {"error": "No file uploaded"}, status=status.HTTP_400_BAD_REQUEST
            )

        # Check the file size
        if file.size > self.MAX_FILE_SIZE:
            return Response(
                {"error": "File size exceeds the maximum limit of 5MB."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Create a FileSystemStorage instance
        fs = FileSystemStorage(location=self.storage_location)

        # Save the file to the uploads directory
        filename = fs.save(file.name, file)

        # Generate the file's URL to be accessed from the frontend
        file_url = fs.url(filename)

        # Check for duplicate files by name or content
        # if is_duplicate(file) and not overwrite:
        #     return Response(
        #         {
        #             "error": "Duplicate file detected. Set 'overwrite' to true to overwrite the existing file."
        #         },
        #         status=status.HTTP_400_BAD_REQUEST,
        #     )

        # Process the file based on its etension
        if file.name.endswith(".csv"):
            result = process_csv(file)
        elif file.name.endswith((".xls", ".xlsx")):
            result = process_excel(file)
        elif file.name.endswith(".json"):
            result = process_json(file)
        elif file.name.endswith(".xml"):
            result = process_xml(file)
        else:
            return Response(
                {
                    "error": "Invalid file format. Please upload a CSV, Excel, JSON, or XML file."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        if "error" in result:
            return Response(result, status=status.HTTP_400_BAD_REQUEST)
        # Return the result with the file URL
        return Response(
            {
                "message": "File processed and saved successfully.",
                "file_url": file_url,  # Provide the file URL for frontend
                "result": result,
            },
            status=status.HTTP_200_OK,
        )


class GetAllVinAPIView(GenericAPIView):
    # authentication_classes = [JWTAuthentication]
    # permission_classes = [IsAuthenticated]
    queryset = CustomDutyFile.objects.all()
    serializer_class = CustomDutyUploadSerializer
    pagination_class = VinPagination

    @swagger_auto_schema(
        operation_summary="Retrieve all Vehicle Identification Numbers (VINs).",
        operation_description="""
            This endpoint retrieves all VINs from the database. 
            It supports pagination for navigating large datasets. 
            The response includes metadata such as total count, next, and previous page links.
        """,
        responses={
            200: openapi.Response(
                description="VINs fetched successfully.",
                examples={
                    "application/json": {
                        "message": "All Vins fetched successfully.",
                        "metadata": {
                            "count": 100,
                            "next": "http://example.com/api/get-all-vins/?page=2",
                            "previous": None,
                            "has_next": True,
                            "has_previous": False,
                            "current_page": 1,
                            "total_pages": 10,
                        },
                        "data": [
                            {
                                "vin": "1HGCM82633A123456",
                                "custom_duty_info": "Duty paid",
                            },
                            {
                                "vin": "2HGCM82633A654321",
                                "custom_duty_info": "Duty unpaid",
                            },
                        ],
                    }
                },
            ),
            400: openapi.Response(
                description="Bad request, error fetching VINs.",
                examples={"application/json": {"error": "Error fetching VIN data"}},
            ),
        },
    )
    def get(self, request, *args, **kwargs):
        """
        Handle GET request to retrieve the list of VINs with pagination.
        """
        queryset = self.get_queryset()

        # Apply pagination if necessary
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        # In case pagination is not applied, return the full dataset
        serializer = self.get_serializer(queryset, many=True)
        return Response(
            {"message": "All Vins fetched successfully.", "data": serializer.data},
            status=status.HTTP_200_OK,
        )
