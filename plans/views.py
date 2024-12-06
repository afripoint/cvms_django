from rest_framework.exceptions import APIException
from drf_yasg.utils import swagger_auto_schema
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from plans.utils import retrieve_wallet_plans, retrieve_wallet_subscription
from products.serializers import (
    ProductCreateSerializer,
    ProductUpdateSerializer,
)
from drf_yasg import openapi


class WalletPlanListAPIView(APIView):
    @swagger_auto_schema(
        operation_summary="list wallet plans",
        operation_description="Allows admin view list of wallet plans",
    )
    def get(self, request, *args, **kwargs):

        try:
            wallet_plans = retrieve_wallet_plans()
            return Response(wallet_plans, status=status.HTTP_200_OK)
        except APIException as e:
            return Response(e.detail, status=status.HTTP_503_SERVICE_UNAVAILABLE)
        except Exception as e:
            error_message = {
                "error": "An unexpected error occurred.",
                "details": str(e),
            }
            return Response(error_message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class WalletSubscriptionListAPIView(APIView):
    @swagger_auto_schema(
        operation_summary="List wallet plans",
        operation_description="Allows admin to view a list of wallet plans.",
        manual_parameters=[
            openapi.Parameter(
                "duration_type",  
                openapi.IN_QUERY,  
                description="Specify the duration type for wallet plans ('month', 'day').",
                type=openapi.TYPE_STRING,
                required=True,  
            ),
        ],
    )
    def get(self, request, *args, **kwargs):

        # Retrieve query parameters
        duration_type = request.query_params.get("duration_type", None)

        # v`alidate required parameters
        if not duration_type:
            return Response(
                {"error": "Missing required parameter 'duration_type'"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Call the retrieve_wallet_subscription function
        try:
            wallet_plans, status_code = retrieve_wallet_subscription(duration_type)

            # Check if an error response is returned
            if status_code != 200:
                return Response(wallet_plans, status=status_code)

            return Response(wallet_plans, status=status.HTTP_200_OK)
        except Exception as e:
            # Handle unexpected errors
            error_message = {
                "error": "An unexpected error occurred.",
                "details": str(e),
            }
            return Response(error_message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
