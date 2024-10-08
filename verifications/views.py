from django.shortcuts import render
from drf_yasg.utils import swagger_auto_schema
import requests
from rest_framework.views import APIView
from rest_framework.response import Response
from drf_yasg import openapi
from rest_framework import status

from verifications.models import Verification


class VerifyCertificateWithQRCodeAPIView(APIView):
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
                        "vin": matching_certificate.get("vin"),
                        "uuid": matching_certificate.get("UUID"),
                        "name": f"{matching_certificate.get('user').get('firstname')} {matching_certificate.get('user').get('surname')}",
                        "vehicle": matching_certificate.get("vehicle"),
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

                return Response(
                    data=data_list,
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
    @swagger_auto_schema(
        operation_summary="Creates report by the enforcement officer after verification",
        operation_description="""
        This endpoint creates a report for after verification.
        
        ### Workflow:
       
        ### Request Fields:
        - **cert_num** (string): The certificate number extracted from the QR code.

        ### Responses:
        - **200 OK**: The certificate was successfully verified, and its status is returned.
        - **404 Not Found**: The certificate number does not match any certificate in the system.
        - **500 Internal Server Error**: Error connecting to the external API.

        ### Example Usage:
        ```
        POST ///
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
        pass