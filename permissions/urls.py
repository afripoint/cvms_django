from django.urls import path

from permissions.views import PermissionListView, RoleListView, RolePermissionUpdateAPIView


urlpatterns = [
    path('', PermissionListView.as_view(), name='permission-list'),
    path('roles/', RoleListView.as_view(), name='roles-list'),
    path('update/<slug:slug>/', RolePermissionUpdateAPIView.as_view(), name='update-permission'),
]
