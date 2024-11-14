from django.shortcuts import render
from django.shortcuts import get_object_or_404
from drf_yasg.utils import swagger_auto_schema
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from products.serializers import (
    ProductCreateSerializer,
    ProductUpdateSerializer,
)
from drf_yasg import openapi

from products.utils import (
    create_product_in_external,
    remove_product_in_external,
    update_product_in_external,
)


class ProductCreationAPIView(APIView):
    @swagger_auto_schema(
        operation_summary="Add a new product",
        operation_description="Allows admin to add a new product to the database",
        request_body=ProductCreateSerializer,
        responses={
            201: openapi.Response(
                description="Product created successfully",
                examples={
                    "application/json": {"message": "Product added successfully"}
                },
            ),
            400: openapi.Response(
                description="Validation error",
                examples={
                    "application/json": {"product_name": ["This field is required."]}
                },
            ),
        },
    )
    def post(self, request):
        serializer = ProductCreateSerializer(data=request.data)
        if serializer.is_valid():
            external_response, external_status = create_product_in_external(
                serializer.validated_data
            )

            return Response(external_response, status=external_status)
        # Return validation errors
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ProductUpdateAPIView(APIView):
    @swagger_auto_schema(
        operation_summary="Update a product",
        operation_description="Allows admin to update an existing product using its slug",
        request_body=ProductUpdateSerializer,
        responses={
            200: openapi.Response(
                description="Product updated successfully",
                examples={
                    "application/json": {"message": "Product updated successfully"}
                },
            ),
            400: openapi.Response(
                description="Validation error",
                examples={
                    "application/json": {"product_name": ["This field is required."]}
                },
            ),
            404: openapi.Response(
                description="Product not found",
                examples={"application/json": {"detail": "Not found."}},
            ),
        },
    )
    def put(self, request, product_id):
        serializer = ProductUpdateSerializer(data=request.data)
        if serializer.is_valid():
            # Call the helper function to update the product in the external API
            external_response, external_status = update_product_in_external(
                product_id, serializer.validated_data
            )

            # Return the external API response and status code
            return Response(external_response, status=external_status)
        else:
            # Return validation errors if serializer is not valid
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# remove a product from the ssystem
class ProductRemoveAPIView(APIView):
    @swagger_auto_schema(
        operation_summary="Remove a product",
        operation_description="Allows admin to removed (soft delete) from the system using its product id",
        responses={
            200: openapi.Response(
                description="Product removed successfully",
                examples={
                    "application/json": {
                        "message": "Product removed from the system successfully"
                    }
                },
            ),
            400: openapi.Response(
                description="Invalid data provided",
                examples={
                    "application/json": {"is_removed": ["This field is required."]}
                },
            ),
            404: openapi.Response(
                description="Product not found",
                examples={"application/json": {"detail": "Not found."}},
            ),
        },
    )
    def delete(self, request, product_id):
         # Call the helper function to delete the product in the external API
        external_response, external_status = remove_product_in_external(product_id)

    
        return Response(external_response, status=external_status)

