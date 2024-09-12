from django.shortcuts import render
from rest_framework.views import APIView
import csv
from rest_framework import status

from data_uploads.utils import process_csv, process_excel
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
                'file': openapi.Schema(type=openapi.TYPE_FILE, description='CSV or Excel file to upload')
            }
        ),
        responses={200: "File processed successfully", 400: "Error processing file"},

    )
    # Define the maximum allowed file size (in bytes)

    def post(self, request, *args, **kwargs):
        # Check if file is in request
        file = request.FILES.get("file")

        if not file:
            return Response(
                {"error": "No file uploaded"}, status=status.HTTP_400_BAD_REQUEST
            )
        
         # Check the file size
        if file.size > self.MAX_FILE_SIZE:
            return Response({"error": "File size exceeds the maximum limit of 5MB."}, status=status.HTTP_400_BAD_REQUEST)

        # Process the file based on its etension
        if file.name.endswith(".csv"):
            result = process_csv(file)
        elif file.name.endswith((".xls", ".xlsx")):
            result = process_excel(file)
        else:
            return Response(
                {"error": "Invalid file format. Please upload a CSV or Excel file."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if "error" in result:
            return Response(result, status=status.HTTP_400_BAD_REQUEST)
        return Response(result, status=status.HTTP_200_OK)


# class GetAllVinAPIView(API)