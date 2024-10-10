from django.shortcuts import render, get_object_or_404
from drf_yasg.utils import swagger_auto_schema
from rest_framework.parsers import MultiPartParser, FormParser
from django.template.loader import render_to_string
from django.conf import settings
from datetime import datetime
import requests
from rest_framework.views import APIView
from rest_framework.response import Response
from drf_yasg import openapi
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from accounts.models import CustomUser
from accounts.utils import send_html_email
from verifications.models import Verification
from verifications.serializer import ReportSerializer, VerificationHistorySerializer


class VerifyCertificateWithQRCodeAPIView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]
    """
    API view to verify payment using cert_num extracted from a QR code.
    """

    @swagger_auto_schema(
        operation_summary="Verify Certificate via QR Code",
        operation_description="""
        This endpoint verifies a certificate's status by its certificate number, which is extracted from a QR code.
        
        ### Workflow:
        1. The user provides the `cert_num` through this endpoint.
        2. The system communicates with an external API to verify the certificate.
        3. If a valid certificate is found, the payment status is checked.
        4. The result is returned to the user, indicating whether the certificate is valid or invalid and whether payment has been made.

        ### Request Fields:
        - **cert_num** (string): The certificate number extracted from the QR code.

        ### Responses:
        - **200 OK**: The certificate was successfully verified, and its status is returned.
        - **404 Not Found**: The certificate number does not match any certificate in the system.
        - **500 Internal Server Error**: Error connecting to the external API.

        ### Example Usage:
        ```
        POST /api/verify_certificate_qr/
        {
            "cert_num": "12345"
        }
        ```

        ### Example Response (Success):
        ```
        HTTP 200 OK
        {
            "certificate_status": "valid",
            "payment_status": "paid",
            "cert_num": "12345"
        }
        ```

        ### Example Response (Failure - Certificate Not Found):
        ```
        HTTP 404 Not Found
        {
            "certificate_status": "Invalid",
            "message": "No certificate found for cert_num: 12345"
        }
        ```

        ### Example Response (Failure - External API Error):
        ```
        HTTP 500 Internal Server Error
        {
            "error": "Unable to connect to external API",
            "details": "Error details here"
        }
        ```
        """,
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "cert_num": openapi.Schema(
                    type=openapi.TYPE_STRING, description="Certificate number"
                )
            },
            required=["cert_num"],
        ),
        responses={
            200: openapi.Response(
                description="Certificate found and status returned",
                examples={
                    "application/json": {
                        "certificate_status": "valid",
                        "payment_status": "paid",
                        "cert_num": "12345",
                    }
                },
            ),
            404: openapi.Response(
                description="Certificate not found",
                examples={
                    "application/json": {
                        "certificate_status": "Invalid",
                        "message": "No certificate found for cert_num: 12345",
                    }
                },
            ),
            500: openapi.Response(
                description="Server error",
                examples={
                    "application/json": {
                        "error": "Unable to connect to external API",
                        "details": "Error details here",
                    }
                },
            ),
        },
    )
    def post(self, request):
        cert_num = request.data.get("cert_num")
        user = request.user

        if not cert_num:
            return Response(
                {"error": "cert_num is required"}, status=status.HTTP_400_BAD_REQUEST
            )

        # external API URL and headers
        api_url = "https://cvmsnigeria.com/api/v1/vehicle/search-history/"
        headers = {"x-secret-key": "rbAZcgfSXQLiHHCzYk8pDU9svNpnoFNZ"}

        # query the API with the uuid
        try:
            response = requests.get(
                f"{api_url}?cert_num={cert_num}", headers=headers, verify=False
            )

            # check if thee uuid eexist and is marked as paid
            if response.status_code == 200:
                # convert to json
                response_data = response.json()
                data_list = response_data.get("data", [])

                if not data_list:
                    return Response(
                        {"error": "Certificate not found"},
                        status=status.HTTP_404_NOT_FOUND,
                    )

                matching_certificate = data_list[0]

                cert_instance, created = Verification.objects.get_or_create(
                    cert_num=matching_certificate.get("cert_num"),
                    defaults={
                        "user": user,
                        "vin": matching_certificate.get("vin"),
                        "uuid": matching_certificate.get("UUID"),
                        "name": f"{matching_certificate.get('user').get('firstname')} {matching_certificate.get('user').get('surname')}",
                        "email": matching_certificate.get("user_id"),
                        "make": matching_certificate.get("manufacturer"),
                        "year": matching_certificate.get("year"),
                        "is_duty_paid": matching_certificate.get("payment_status"),
                    },
                )
                # search the certificate list
                # matching_certificate = next(
                #     (cert for cert in data_list if cert.get("cert_num") == cert_num),
                #     None,
                # )

                # if matching_certificate:
                #     payment_status = matching_certificate.get("payment_status", None)

                #     if payment_status is True:
                #         response = {
                #             "certificate_status": "valid",
                #             "payment_status": "paid",
                #             "cert_num": matching_certificate.get("cert_num"),
                #         }
                #         return Response(data=response, status=status.HTTP_200_OK)
                #     elif payment_status is False:
                #         response = {
                #             "certificate_status": "valid",
                #             "payment_status": "unpaid",
                #             "cert_num": matching_certificate.get("cert_num"),
                #         }
                #         return Response(data=response, status=status.HTTP_200_OK)
                # else:
                #     # If no certificate matches the cert_num
                #     response = {
                #         "certificate_status": "Invalid",
                #         "message": f"No certificate found for cert_num: {cert_num}",
                #     }
                #     return Response(data=response, status=status.HTTP_404_NOT_FOUND)

                response = {
                    "message": "certificate fetch successfully",
                    "data": data_list,
                    "slug": cert_instance.uuid,
                }

                return Response(
                    data=response,
                    status=status.HTTP_200_OK,
                )
            return Response(
                {"error": "data not found"}, status=status.HTTP_404_NOT_FOUND
            )
        except requests.exceptions.RequestException as e:
            # Handle any error in the external API call
            return Response(
                {"error": "Unable to connect to external API", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class CreateReportAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser]
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    @swagger_auto_schema(
        operation_summary="Creates report by the enforcement officer after verification",
        # request_body=ReportSerializer,
    )
    def post(self, request, slug):
        vin = get_object_or_404(Verification, uuid=slug)
        now = datetime.now()
        current_time = now.strftime("%Y-%m-%d %H:%M:%S")
        user = request.user
        serializer = ReportSerializer(
            data=request.data, context={"request": request, "vin": vin}
        )

        if serializer.is_valid():
            serializer.save()
            query_type = serializer.validated_data["query_type"]
            recipient_email_admin = "admin@cvmsnigeria.com"

            subject = (
                "New Issue Report Submitted on CVMS — Immediate Attention Requiredt"
            )

            message_user = render_to_string(
                "verifications/notification.html",
                {
                    "query_type": query_type,
                    "time_stamp": current_time,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                },
            )

            send_html_email(
                subject=subject,
                body=message_user,
                from_email=settings.DEFAULT_FROM_EMAIL,
                to_email=[recipient_email_admin],
            )

            response = {
                "message": "report created and submitted successfully",
                "data": serializer.data,
            }
            return Response(data=response, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# List reports
class VerificationHistoryAPIView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    @swagger_auto_schema(
        operation_summary="Retrieve Verification History for Enforcement Officer",
        operation_description="""
        This endpoint retrieves the verification history for an enforcement officer.

        ### Workflow:
        1. The authenticated user (enforcement officer) makes a request to this endpoint.
        2. The system fetches all previous verifications associated with the user.
        3. The history of verifications is returned, including relevant certificate information.

        ### Request:
        This is a **GET** request; no additional fields are required in the body.

        ### Responses:
        - **200 OK**: A list of verification history is returned.
        - **404 Not Found**: No verification history found for the user.
        - **500 Internal Server Error**: Internal server error while processing the request.

        ### Example Usage:
        ```
        GET /api/verification-history/
        ```

        ### Example Response (Success):
        ```json
        HTTP 200 OK
        {
            "message": [
                {
                    "cert_num": "12345",
                    "certificate_status": "valid",
                    "payment_status": "paid",
                    "verified_at": "2024-10-08T12:34:56Z"
                },
                {
                    "cert_num": "67890",
                    "certificate_status": "invalid",
                    "payment_status": "unpaid",
                    "verified_at": "2024-09-15T11:22:33Z"
                }
            ]
        }
        ```

        ### Example Response (No History Found):
        ```json
        HTTP 404 Not Found
        {
            "message": "No verification history found for the user."
        }
        ```

        ### Example Response (Internal Server Error):
        ```json
        HTTP 500 Internal Server Error
        {
            "error": "Unable to fetch verification history.",
            "details": "Detailed error message here."
        }
        ```
        """,
        responses={
            200: "Verification history retrieved successfully",
            404: "No verification history found",
            500: "Internal server error",
        },
    )
    def get(self, request):
        user = request.user
        verifications = Verification.objects.filter(user=user)

        if not verifications.exists():
            return Response(
                {"message": "No verification history found for the user."},
                status=status.HTTP_404_NOT_FOUND,
            )
        serializer = VerificationHistorySerializer(verifications, many=True)

        response = {
            "message": serializer.data,
        }
        return Response(data=response, status=status.HTTP_200_OK)


class VerificationDetailAPIView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    @swagger_auto_schema(
        operation_summary="Retrieve Verification Details",
        operation_description="""
        This endpoint retrieves the details of a specific verification associated with the authenticated user.

        ### Workflow:
        1. The authenticated user makes a request to this endpoint with the verification identifier (slug).
        2. The system fetches the verification details corresponding to the provided slug.
        3. The details of the verification are returned to the user.

        ### Request:
        This is a **GET** request. The slug must be provided as a path parameter.

        ### Responses:
        - **200 OK**: Verification details are successfully retrieved.
        - **404 Not Found**: The verification with the provided slug does not exist or does not belong to the authenticated user.
        - **500 Internal Server Error**: Internal server error while processing the request.

        ### Example Usage:
        ```
        GET /api/verification-detail/{slug}/
        ```

        ### Example Response (Success):
        ```json
        HTTP 200 OK
        {
            "message": {
                "cert_num": "12345",
                "certificate_status": "valid",
                "payment_status": "paid",
                "verified_at": "2024-10-08T12:34:56Z",
                "user": {
                    "username": "enforcement_officer",
                    "email": "officer@example.com"
                }
            }
        }
        ```

        ### Example Response (Not Found):
        ```json
        HTTP 404 Not Found
        {
            "message": "Verification with the given identifier not found."
        }
        ```

        ### Example Response (Internal Server Error):
        ```json
        HTTP 500 Internal Server Error
        {
            "error": "Unable to fetch verification detail.",
            "details": "Detailed error message here."
        }
        ```
        """,
        responses={
            200: "Verification detail retrieved successfully",
            404: "Verification not found",
            500: "Internal server error",
        },
    )
    def get(self, request, slug):
        user = request.usser
        verification = get_object_or_404(Verification, uuid=slug, user=user)
        serializer = VerificationHistorySerializer(verification)

        response = {
            "message": serializer.data,
        }
        return Response(data=response, status=status.HTTP_200_OK)
