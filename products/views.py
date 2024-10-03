from django.shortcuts import render
from drf_yasg.utils import swagger_auto_schema
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView

from products.models import Product
from products.serializers import ProductSerilizer


class ProductListAPIView(APIView):
    @swagger_auto_schema(
        operation_summary="This list all product",
        operation_description="Allows admin to view all products in the database",
        # request_body=ProductSerilizer,
    )
    def get(self, request):
        products = Product.objects.all()
        serializer = ProductSerilizer(products, many=True)

        response = {
            "message": serializer.data,
        }

        return Response(data=response, status=status.HTTP_200_OK)
    

class ProductListAPIView(APIView):
    @swagger_auto_schema(
        operation_summary="This add all product",
        operation_description="Allows admin to view all products in the database",
        request_body=ProductSerilizer,
    )
    def post(self, request):
        data = request.data
        serializer = ProductSerilizer(data=data)

        if serializer.is_valid():
            serializer.save()
            response = {"message": "Product added successfully"}
            return Response(data=response, status=status.HTTP_201_CREATED)
        return Response({"Invalide data entry"}, status=status.HTTP_400_BAD_REQUEST)
    

class ProductUpdateAPIView(APIView):
    pass

