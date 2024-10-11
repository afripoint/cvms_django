from django.shortcuts import render, get_object_or_404
from rest_framework import status
from rest_framework.response import Response
from drf_yasg.utils import swagger_auto_schema
from rest_framework.views import APIView
from rest_framework.permissions import IsAdminUser
from .serializers import PermissionSerializer, RolePermissionUpdateSerializer, RoleSerializer
from .models import Permission
from roles.models import Role
from drf_yasg import openapi


class PermissionListView(APIView):
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
                                "created_at": "2024-10-10T12:00:00Z"
                            },
                            {
                                "name": "Delete Records",
                                "permission_code": "delete_records",
                                "created_at": "2024-10-11T08:00:00Z"
                            }
                        ]
                    }
                }
            )
        }
    )
    def get(self, request):
        permissions = Permission.objects.all()
        serializer = PermissionSerializer(permissions, many=True)
        response = {
            "message": serializer.data,
        }
        return Response(data=response, status=status.HTTP_200_OK)


class RoleListView(APIView):
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
                                        "created_at": "2024-10-10T12:00:00Z"
                                    },
                                    {
                                        "name": "Edit Profile",
                                        "permission_code": "edit_profile",
                                        "created_at": "2024-10-11T09:30:00Z"
                                    }
                                ]
                            },
                            {
                                "role": "Moderator",
                                "permissions": [
                                    {
                                        "name": "View Users",
                                        "permission_code": "view_users",
                                        "created_at": "2024-10-09T11:15:00Z"
                                    }
                                ]
                            }
                        ]
                    }
                }
            )
        }
    )
    def get(self, request):
        roles = Role.objects.all()
        serializer = RoleSerializer(roles, many=True)

        response = {"all roles": serializer.data}
        return Response(data=response, status=status.HTTP_200_OK)


class RolePermissionUpdateAPIView(APIView):
    permission_classes = [IsAdminUser]

    @swagger_auto_schema(
        operation_summary="Update Role Permissions (Admin Only)",
        operation_description="""
        This endpoint allows an admin to update permissions for a specific role.
        The admin must provide the following details in the request:
        
        - **role_id:** The ID of the role for which permissions are being updated.
        - **permissions:** A list of permission codes to assign to the role.

        ### Example Usage:
        ```
        PATCH /api/roles/permissions/update/
        {
            "role_id": 1,
            "permissions": ["create_user", "delete_records", "edit_profile"]
        }
        ```

        ### Example Responses:
        - **Success (200 OK):**
        ```
        {
            "message": "Role permissions updated successfully"
        }
        ```

        - **Role Not Found (404 Not Found):**
        ```
        {
            "detail": "Role not found."
        }
        ```

        - **Invalid Permissions (400 Bad Request):**
        ```
        {
            "permissions": ["Invalid permission codes provided."]
        }
        ```

        ### Requirements:
        - User must be authenticated as an admin.
        - The provided permissions must be valid and exist in the system.
        """,
        request_body=RolePermissionUpdateSerializer,
    )

    def patch(self, request, slug):
        
        """
        Update permissions for a role dynamically.
        Expected input: {'permissions': ['upload_files', 'view_all_users']}
        """
        role = get_object_or_404(Role, slug=slug)
        permission_codes = request.data.get('permissions', [])

        if permission_codes:
            permissions = Permission.objects.filter(permission_code__in=permission_codes)
            role.permissions.set(permissions)
            role.save()
            return Response({"message": "Permissions updated successfully."}, status=status.HTTP_200_OK)

        return Response({"error": "Invalid data."}, status=status.HTTP_400_BAD_REQUEST)
