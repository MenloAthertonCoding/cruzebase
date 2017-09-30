from django.utils import timezone

from rest_framework import permissions

from auth.models import UserProfile

class IsAdminOrIsSelf(permissions.BasePermission):
    """ Custom permission to only allow admins or owners of an object to edit it.
    """
    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed to any request,
        # so we'll always allow GET, HEAD or OPTIONS requests.
        if request.method in permissions.SAFE_METHODS:
            return True

        # Write permissions are only allowed to the user or administrator
        return request.user and (obj.user == request.user or
                                 (request.user.is_staff or request.user.is_superuser))


class IsNotSuspended(permissions.BasePermission):
    """Custom permission to permit only non suspended user's requests.
    """
    def has_permission(self, request, view):
        # Read permissions are allowed to any request,
        # so we'll always allow GET, HEAD or OPTIONS requests.
        if request.method in permissions.SAFE_METHODS:
            return True

        # Permissions are only given to users that are not suspended
        if request.user:
            if not request.user.is_authenticated:
                return True

            # TODO Ensure that related objects exist
            user_profile = UserProfile.objects.get(user=request.user)

            if user_profile.suspended_until is None:
                return True

            if user_profile.suspended_until < timezone.now():
                # The suspension time has elapsed, update UserProfile
                UserProfile.objects.filter(pk=user_profile.pk).update(
                    suspended_until=None,
                    last_suspension=timezone.now()
                )
                # return True as the user is no longer suspended
                return True

        return False
