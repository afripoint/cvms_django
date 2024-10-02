from django.urls import path

from permissions.views import PermissionListView, RoleListView, RolePermissionAPIView


urlpatterns = [
    path('', PermissionListView.as_view(), name='permission-list'),
    path('roles/', RoleListView.as_view(), name='roles-list'),
    path('roles/<slug:slug>/', RolePermissionAPIView.as_view(), name='role-permissions'),
]
