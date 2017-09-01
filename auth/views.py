from django.contrib.auth.models import User as DjangoUser
from django.shortcuts import get_object_or_404

from rest_framework import viewsets
from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import detail_route

from auth.serializers import UserProfileSerializer
from auth.models import UserProfile
from auth.permissions import IsAdminOrIsSelf


class UserProfileViewSet(viewsets.ModelViewSet):
    """
    A viewset for viewing and modifing user instances.
    """
    serializer_class = UserProfileSerializer
    queryset = UserProfile.objects.filter(user__is_active=True)
    permission_classes = (IsAdminOrIsSelf,) # TODO Add IP Blacklist permission

    def destroy(self, request, pk=None):
        """
        Instead of deleting the `UserProfile` and Django `User` object,
        Django `User`'s `is_active` is set to false.
        """
        user = self.get_object()
        user.user.is_active = False
        user.user.save()

        return Response()

    @detail_route(methods=['post'], permission_classes=[IsAdminOrIsSelf])
    def set_password(self, request, pk=None):
        """Sets a users password"""
        # TODO implement
        return Response(status=status.HTTP_501_NOT_IMPLEMENTED)
