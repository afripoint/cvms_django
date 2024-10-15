from django.shortcuts import render, get_object_or_404
from rest_framework import status
from rest_framework.response import Response
from drf_yasg.utils import swagger_auto_schema
from rest_framework.views import APIView
from rest_framework.permissions import IsAdminUser
from .serializers import (
    PermissionLogSerializer,
    PermissionSerializer,
    RolesSerializer,
    RolesWithPermissionsSerializer,
)
from .models import Permission, PermissionsLog
from roles.models import Role
from drf_yasg import openapi
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication


class PermissionListAPIView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser]
    authentication_classes = [JWTAuthentication]

    @swagger_auto_schema(
        operation_summary="List all permissions",
        operation_description="Returns a list of all permissions available in the system.",
        responses={
            200: openapi.Response(
                description="A list of permissions",
                examples={
                    "application/json": {
                        "message": [
                            {
                                "name": "Create User",
                                "permission_code": "create_user",
                                "created_at": "2024-10-10T12:00:00Z",
                            },
                            {
                                "name": "Delete Records",
                                "permission_code": "delete_records",
                                "created_at": "2024-10-11T08:00:00Z",
                            },
                        ]
                    }
                },
            )
        },
    )
    def get(self, request):
        permissions = Permission.objects.all()
        serializer = PermissionSerializer(permissions, many=True)
        return Response(serializer.data)


class PermissionCreateAPIView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser]
    authentication_classes = [JWTAuthentication]

    def get_client_ip(self, request):
        """Helper method to extract client IP from request"""
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            ip = x_forwarded_for.split(",")[0]
        else:
            ip = request.META.get("REMOTE_ADDR")
        return ip

    @swagger_auto_schema(
        operation_summary="Create a new permission",
        operation_description="Creates a new permission with the provided name and permission_code.",
        request_body=PermissionSerializer,
        responses={
            201: openapi.Response(
                description="Permission created successfully",
                examples={
                    "application/json": {
                        "name": "Create User",
                        "permission_code": "create_user",
                        "created_at": "2024-10-10T12:00:00Z",
                    }
                },
            ),
            400: "Bad Request",
        },
    )
    def post(self, request):
        serializer = PermissionSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()

            PermissionsLog.objects.create(
                created_by=request.user,
                event_type="create permission",
                description="A new permission was created",
                ip_address=self.get_client_ip(request),
            )
            response = {
                "message": "Permission created",
                "data": serializer.data,
            }
            return Response(data=response, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class RoleListAPIView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser]
    authentication_classes = [JWTAuthentication]

    @swagger_auto_schema(
        operation_summary="List all roles with permissions",
        operation_description="Returns a list of all roles and the permissions assigned to each role.",
        responses={
            200: openapi.Response(
                description="A list of roles with permissions",
                examples={
                    "application/json": {
                        "all roles": [
                            {
                                "role": "Admin",
                                "permissions": [
                                    {
                                        "name": "Create User",
                                        "permission_code": "create_user",
                                        "created_at": "2024-10-10T12:00:00Z",
                                    },
                                    {
                                        "name": "Edit Profile",
                                        "permission_code": "edit_profile",
                                        "created_at": "2024-10-11T09:30:00Z",
                                    },
                                ],
                            },
                            {
                                "role": "Moderator",
                                "permissions": [
                                    {
                                        "name": "View Users",
                                        "permission_code": "view_users",
                                        "created_at": "2024-10-09T11:15:00Z",
                                    }
                                ],
                            },
                        ]
                    }
                },
            )
        },
    )
    def get(self, request):
        roles = Role.objects.all()
        serializer = RolesWithPermissionsSerializer(roles, many=True)
        return Response(serializer.data)


class RoleDetailAPIView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser]
    authentication_classes = [JWTAuthentication]

    @swagger_auto_schema(
        operation_summary="Retrieve role details",
        operation_description="Retrieve the details of a role and its associated permissions by slug.",
        responses={
            200: openapi.Response(
                description="Role details retrieved successfully",
                examples={
                    "application/json": {
                        "all roles": {
                            "role": "Admin",
                            "permissions": [
                                {
                                    "name": "Create User",
                                    "permission_code": "create_user",
                                    "created_at": "2024-10-10T12:00:00Z",
                                },
                                {
                                    "name": "Edit Profile",
                                    "permission_code": "edit_profile",
                                    "created_at": "2024-10-11T09:30:00Z",
                                },
                            ],
                        }
                    }
                },
            ),
        },
    )
    def get(self, request, slug):
        role = get_object_or_404(Role, slug=slug)
        serializer = RolesSerializer(role)
        response = {
            "all roles": serializer.data,
        }
        return Response(data=response, status=status.HTTP_200_OK)
    



class CreatRolePermission(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser]
    authentication_classes = [JWTAuthentication]

    def get_client_ip(self, request):
        """Helper method to extract client IP from request"""
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            ip = x_forwarded_for.split(",")[0]
        else:
            ip = request.META.get("REMOTE_ADDR")
        return ip

    @swagger_auto_schema(
        operation_summary="Create a new role",
        operation_description="Creates a new role and assigns permissions to it.",
        request_body=RolesSerializer,
        responses={
            201: openapi.Response(
                description="Role created successfully",
                examples={
                    "application/json": {
                        "role": "Admin",
                        "permissions": [
                            {
                                "name": "Create User",
                                "permission_code": "create_user",
                                "created_at": "2024-10-10T12:00:00Z",
                            },
                            {
                                "name": "Edit Profile",
                                "permission_code": "edit_profile",
                                "created_at": "2024-10-11T09:30:00Z",
                            },
                        ],
                    }
                },
            ),
            400: "Bad Request",
        },
    )
    def post(self, request):
        serializer = RolesSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()

            PermissionsLog.objects.create(
                created_by=request.user,
                event_type="create role",
                description="A new role was created",
                ip_address=self.get_client_ip(request),
            )
            response = {
                "message": "Role and permissions created successfully",
                "data": serializer.data,
            }
            return Response(data=response, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class RoleUpdateAPIView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser]
    authentication_classes = [JWTAuthentication]

    def get_client_ip(self, request):
        """Helper method to extract client IP from request"""
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            ip = x_forwarded_for.split(",")[0]
        else:
            ip = request.META.get("REMOTE_ADDR")
        return ip

    @swagger_auto_schema(
        operation_summary="Update a role",
        operation_description="Update a role's details and its permissions by slug.",
        request_body=RolesSerializer,
        responses={
            200: openapi.Response(
                description="Role updated successfully",
                examples={
                    "application/json": {
                        "Role updated successfully": {
                            "role": "Admin",
                            "permissions": [
                                {
                                    "name": "Create User",
                                    "permission_code": "create_user",
                                    "created_at": "2024-10-10T12:00:00Z",
                                },
                                {
                                    "name": "Edit Profile",
                                    "permission_code": "edit_profile",
                                    "created_at": "2024-10-11T09:30:00Z",
                                },
                            ],
                        }
                    }
                },
            ),
            400: "Bad Request",
        },
    )
    def put(self, request, slug):
        role = get_object_or_404(Role, slug=slug)
        serializer = RolesSerializer(role, data=request.data)
        if serializer.is_valid():
            serializer.save()

            PermissionsLog.objects.create(
                created_by=request.user,
                event_type="update role",
                description=f"A role - {role.slug} was created",
                ip_address=self.get_client_ip(request),
            )
            response = {
                "Role updated successfully": serializer.data,
            }
            return Response(data=response, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class RoleDeleteAPIView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser]
    authentication_classes = [JWTAuthentication]

    def get_client_ip(self, request):
        """Helper method to extract client IP from request"""
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            ip = x_forwarded_for.split(",")[0]
        else:
            ip = request.META.get("REMOTE_ADDR")
        return ip

    @swagger_auto_schema(
        operation_summary="Delete a role",
        operation_description="Deletes a role by its slug.",
        request_body=RolesSerializer,
        responses={
            204: "Role deleted successfully",
        },
    )
    def delete(self, request, slug):
        role = get_object_or_404(Role, slug=slug)
        role.delete()

        PermissionsLog.objects.create(
            created_by=request.user,
            event_type="delete role",
            description=f"A role - {role.slug} was deleted",
            ip_address=self.get_client_ip(request),
        )
        response = {"message": "Role deleted successfully"}
        return Response(data=response, status=status.HTTP_204_NO_CONTENT)


class PermissionLogAPIView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser]
    authentication_classes = [JWTAuthentication]

    @swagger_auto_schema(
        operation_summary="List all permisssions logs",
        operation_description="List all logs for permission.",

        
    )
    def get(self, request):
        permission_log = PermissionsLog.objects.all()
        serializer = PermissionLogSerializer(permission_log, many=True)

        response = {
            "message": "All Permission logs",
            "data": serializer.data
        }
        return Response(data=response, status=status.HTTP_200_OK)