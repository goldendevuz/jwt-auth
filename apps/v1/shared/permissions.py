from rest_framework.permissions import BasePermission


class HasCompletedSignup(BasePermission):
    def has_permission(self, request, view):
        print(getattr(request.user, "auth_status", None))
        return getattr(request.user, "auth_status", None) == "photo_done"
