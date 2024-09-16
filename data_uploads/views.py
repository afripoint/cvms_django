from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.core.files.storage import FileSystemStorage
import csv
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
        operation_summary="This endpoint handle file upload (CSV or Excel) and update the Custom Duty Payment.",
        operation_description="handle file upload (CSV or Excel) and update the Custom Duty Payment.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "file": openapi.Schema(
                    type=openapi.TYPE_FILE, description="CSV or Excel file to upload"
                )
            },
        ),
        responses={200: "File processed successfully", 400: "Error processing file"},
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


class GetAllVinAPIView(APIView):
    # authentication_classes = [JWTAuthentication]
    # permission_classes = [IsAuthenticated]
    pagination_class = VinPagination

    @swagger_auto_schema(
        operation_summary="This endpoint gets all VIN.",
        operation_description="handles the getting all VIN",
    )
    def get(self, request, *args, **kwargs):
        all_vin = CustomDutyFile.objects.all()

        # Initialize the paginator
        paginator = self.pagination_class()

        # Paginate the queryset
        page = paginator.paginate_queryset(all_vin, request, view=self)

        # Serialize the data
        serializer = CustomDutyUploadSerializer(page, many=True)

        # Construct the response
        paginated_response_data = paginator.get_paginated_response(serializer.data).data

        # Construct the custom response with separate metadata object
        custom_response_data = {
            "message": "All Vins fetched successfully.",
            "metadata": {
                "count": paginated_response_data.get("count"),
                "next": paginated_response_data.get("next"),
                "previous": paginated_response_data.get("previous"),
            },
            "data": paginated_response_data.get("results"),
        }

        return Response(data=custom_response_data, status=status.HTTP_200_OK)
