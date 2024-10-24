from django.shortcuts import render
from django.shortcuts import render, get_object_or_404
from rest_framework import status
from rest_framework.response import Response
from drf_yasg.utils import swagger_auto_schema
from rest_framework.views import APIView
from rest_framework.permissions import IsAdminUser
from accounts.models import CVMSAuthLog
from drf_yasg import openapi
from accounts.signals import get_client_ip
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication

from tracker.models import Consignment, TrackingRecord
from tracker.serializer import (
    ConsignmentRegisterSeriliazer,
    ConsignmentUpdateSerializer,
)


class ConsignmentRegistrationAPIView(APIView):
    # permission_classes = [IsAuthenticated, IsAdminUser]
    # authentication_classes = [JWTAuthentication]

    @swagger_auto_schema(
        operation_summary="Create a consigment record for an importer",
        operation_description="Creates a consignment record for an importer.",
        request_body=ConsignmentRegisterSeriliazer,
    )
    def post(self, request):
        data = request.data
        serializer = ConsignmentRegisterSeriliazer(data=data)

        if serializer.is_valid():
            serializer.save()

            try:
                registration_officer = serializer.validated_data["registration_officer"]

                consignment_instance = Consignment.objects.get(
                    registration_officer=registration_officer
                )

                TrackingRecord.objects.create(
                    created_by=consignment_instance,
                    tracking_status="tracking created",
                )

            except Exception as e:
                return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

            response = {
                "message": "consignment record created successfully",
                "data": serializer.data,
            }

            return Response(data=response, status=status.HTTP_201_CREATED)
        return Response(
            data=serializer.error_messages, status=status.HTTP_400_BAD_REQUEST
        )


class ConsignmentUpdateAPIView(APIView):
    @swagger_auto_schema(
        operation_summary="Updating a record for tracking by the importer",
        operation_description="Update a consignment record for an importer to be able to track.",
        request_body=ConsignmentUpdateSerializer,
    )
    def patch(self, request, slug):
        instance = get_object_or_404(Consignment, slug=slug)
        serializer = ConsignmentUpdateSerializer(
            instance, data=request.data, partial=True
        )
        if serializer.is_valid():
            try:
                registration_officer = serializer.validated_data["registration_officer"]
                TrackingRecord.objects.create(
                    created_by=instance,
                    updated_by=registration_officer,
                    tracking_status="tracking updated",
                )
                serializer.save()

            except Exception as e:
                return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

            response = {
                "message": "consignment record updated successfully",
            }

            return Response(data=response, status=status.HTTP_201_CREATED)
        return Response(
            data=serializer.error_messages, status=status.HTTP_400_BAD_REQUEST
        )
