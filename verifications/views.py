from django.shortcuts import render
from drf_yasg.utils import swagger_auto_schema
import requests
from rest_framework.views import APIView
from rest_framework.response import Response
from drf_yasg import openapi
from rest_framework import status


class VerifyCertificateWithQRCodeAPIView(APIView):
    """
    API view to verify payment using cert_num extracted from a QR code.
    """

    @swagger_auto_schema(
        operation_description="Verify certificate status by certificate number.",
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
                description="Successful response",
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
                    "data": data_list,
                }

                return Response(
                    data=response,
                    status=status.HTTP_200_OK,
                )
            return Response(
                {"error": "data not found"}, status=status.HTTP_404_NOT_FOUND
            )

            # return Response(
            #     {"error": "data not found"},
            #     status=status.HTTP_400_INTERNAL_SERVER_ERROR,
            # )
        except requests.exceptions.RequestException as e:
            # Handle any error in the external API call
            return Response(
                {"error": "Unable to connect to external API", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
