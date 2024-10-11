from django.shortcuts import render
from django.shortcuts import get_object_or_404
from drf_yasg.utils import swagger_auto_schema
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView

from products.models import Product
from products.serializers import ProductRemoveSerializer, ProductSerializer
from drf_yasg import openapi


class ProductListAPIView(APIView):
    @swagger_auto_schema(
        operation_summary="List all products",
        operation_description="Allows admin to view all active (non-removed) products in the database",
        responses={
            200: openapi.Response(
                description="List of products",
                examples={
                    "application/json": {
                        "message": [
                            {
                                "product_name": "Sample Product",
                                "product_description": "Description of the product",
                                "product_price": 100.00,
                                "is_removed": False,
                                "created_at": "2024-10-10T12:00:00Z",
                            }
                        ]
                    }
                },
            )
        },
    )
    def get(self, request):
        products = Product.objects.filter(is_removed=False)
        serializer = ProductSerializer(products, many=True)

        response = {
            "message": serializer.data,
        }

        return Response(data=response, status=status.HTTP_200_OK)


class ProductCreationAPIView(APIView):

    @swagger_auto_schema(
        operation_summary="Add a new product",
        operation_description="Allows admin to add a new product to the database",
        request_body=ProductSerializer,
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
        data = request.data
        serializer = ProductSerializer(data=data)

        if serializer.is_valid():
            serializer.save()
            response = {"message": "Product added successfully"}
            return Response(data=response, status=status.HTTP_201_CREATED)
        # Return validation errors
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ProductRetrieveAPIView(APIView):
    @swagger_auto_schema(
        operation_summary="Retrieve a single product",
        operation_description="Allows admin to retrieve a product by its slug",
        responses={
            200: openapi.Response(
                description="Product details retrieved",
                examples={
                    "application/json": {
                        "message": {
                            "product_name": "Sample Product",
                            "product_description": "Description of the product",
                            "product_price": 100.00,
                            "is_removed": False,
                            "created_at": "2024-10-10T12:00:00Z",
                        }
                    }
                },
            ),
            404: openapi.Response(
                description="Product not found",
                examples={"application/json": {"detail": "Not found."}},
            ),
        },
    )
    def get(self, request, slug):
        product = get_object_or_404(Product, slug=slug)
        serializer = ProductSerializer(product)

        response = {
            "message": serializer.data,
        }
        return Response(data=response, status=status.HTTP_200_OK)


class ProductUpdateAPIView(APIView):
    @swagger_auto_schema(
        operation_summary="Update a product",
        operation_description="Allows admin to update an existing product using its slug",
        request_body=ProductSerializer,
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
    def patch(self, request, slug):
        product = get_object_or_404(Product, slug=slug)
        serializer = ProductSerializer(product, data=request.data, partial=True)

        if serializer.is_valid():
            serializer.save()

            response = {
                "message": "Product updated successfully",
            }
            return Response(data=response, status=status.HTTP_200_OK)
        # Return validation errors
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# reove a product from the ssystem
class ProductRemoveAPIView(APIView):
    @swagger_auto_schema(
        operation_summary="Remove a product",
        operation_description="Allows admin to mark a product as removed (soft delete) from the system using its slug",
        request_body=ProductRemoveSerializer,
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
    def patch(self, request, slug):
        product = Product.objects.get(is_removed=False, slug=slug)
        serializer = ProductRemoveSerializer(product, data=request.data)

        if serializer.is_valid():
            serializer.save()

            response = {
                "message": "product removed from the system successfully",
            }
            return Response(data=response, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
