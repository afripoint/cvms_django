from django.shortcuts import render
from django.shortcuts import get_object_or_404
from drf_yasg.utils import swagger_auto_schema
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView

from products.models import Product
from products.serializers import ProductRemoveSerializer, ProductSerilizer


class ProductListAPIView(APIView):
    @swagger_auto_schema(
        operation_summary="This list all product",
        operation_description="Allows admin to view all products in the database",
    )
    def get(self, request):
        products = Product.objects.filter(is_removed=False)
        serializer = ProductSerilizer(products, many=True)

        response = {
            "message": serializer.data,
        }

        return Response(data=response, status=status.HTTP_200_OK)


class ProductCreationAPIView(APIView):
    @swagger_auto_schema(
        operation_summary="This endpoint adds a product",
        operation_description="Allows user to add a product to the database",
        request_body=ProductSerilizer,
    )
    def post(self, request):
        data = request.data
        serializer = ProductSerilizer(data=data)

        if serializer.is_valid():
            serializer.save()
            response = {"message": "Product added successfully"}
            return Response(data=response, status=status.HTTP_201_CREATED)
         # Return validation errors
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ProductRetrieveAPIView(APIView):
    @swagger_auto_schema(
        operation_summary="This endpoint gets a single product",
        operation_description="Allows user to retrieve a single product from the database",
    )
    def get(self, request, slug):
        product = get_object_or_404(Product, slug=slug)
        serializer = ProductSerilizer(product)

        response = {
            "message": serializer.data,
        }
        return Response(data=response, status=status.HTTP_200_OK)


class ProductUpdateAPIView(APIView):
    @swagger_auto_schema(
        operation_summary="This endpoint allows the update of a product",
        operation_description="Allows user to retrieve and update a single product",
    )
    def put(self, request, slug):
        product = get_object_or_404(Product, slug=slug)
        serializer = ProductSerilizer(product, data=request.data, partial=True)

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
        operation_summary="This endpoint allow the removal of a product from the system",
        operation_description="Allows the removal of a product from the system",
        request_body=ProductRemoveSerializer
    )
    def put(self, request, slug):
        product = Product.objects.get(is_removed=False, slug=slug)
        serializer = ProductRemoveSerializer(product, data=request.data)

        if serializer.is_valid():
            serializer.save()

            response = {
                "message": "product removed from the system successfully",
            }
            return Response(data=response, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)