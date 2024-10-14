from rest_framework.permissions import BasePermission


class HasPermission(BasePermission):
    """
    Custom permission to check if a user has a specific permission.
    """

    def has_permission(self, request, view):

        permission_code = getattr(view, "required_permission", None)

        if permission_code:
            return request.user.has_permission(permission_code)
        return False
