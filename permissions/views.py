from django.shortcuts import render, get_object_or_404
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAdminUser
from .serializers import PermissionSerializer, RoleSerializer
from .models import Permission
from roles.models import Role


class PermissionListView(APIView):
    def get(self, request):
        permissions = Permission.objects.all()
        serializer = PermissionSerializer(permissions, many=True)
        response = {
            "message": serializer.data,
        }
        return Response(data=response, status=status.HTTP_200_OK)


class RoleListView(APIView):
    def get(self, request):
        roles = Role.objects.all()
        serializer = RoleSerializer(roles, many=True)

        response = {"all roles": serializer.data}
        return Response(data=response, status=status.HTTP_200_OK)


class RolePermissionAPIView(APIView):
    def get(self, request, slug):
        # Get the details of a specific role, including its permissions.
        role = get_object_or_404(Role, slug=slug)

        # Serialize the role data, including its permissions
        serializer = RoleSerializer(role)

        # Return the role details as a JSON response
        response = {"role": serializer.data}
        return Response(data=response, status=status.HTTP_200_OK)

    def patch(self, request, slug):
        # Update the permissions for a specific role.
        role = get_object_or_404(Role, slug=slug)

        serializer = RoleSerializer(role, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            response = {"permission updated successfully": serializer.data}

            return Response(data=response, status=status.HTTP_200_OK)
