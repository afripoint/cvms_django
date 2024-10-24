from django.urls import path

from permissions.views import (
    CreatRolePermission,
    PermissionCreateAPIView,
    PermissionListAPIView,
    PermissionLogAPIView,
    RoleDeleteAPIView,
    RoleDetailAPIView,
    RoleListAPIView,
    RoleUpdateAPIView,
)


urlpatterns = [
    path("", PermissionListAPIView.as_view(), name="permission-list"),
    path("create/", PermissionCreateAPIView.as_view(), name="permission-list"),
    path("roles/", RoleListAPIView.as_view(), name="roles-list"),
    path("role/create/", CreatRolePermission.as_view(), name="roles-create"),
    path("role/detail/<slug:slug>/", RoleDetailAPIView.as_view(), name="role-detail"),
    path("role/update/<slug:slug>/", RoleUpdateAPIView.as_view(), name="roles-update"),
    path("role/delete/<slug:slug>/", RoleDeleteAPIView.as_view(), name="roles-delete"),
    path("logs/", PermissionLogAPIView.as_view(), name="permisssion-logs"),
]
