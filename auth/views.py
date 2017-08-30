from django.contrib.auth.models import User

from rest_framework import viewsets
from rest_framework import permissions

from auth.serializers import UserProfileSerializer
from auth.models import UserProfile

class UserProfileViewSet(viewsets.ModelViewSet):
    """
    A viewset for viewing and modifing user instances.
    """
    serializer_class = UserProfileSerializer
    queryset = UserProfile.objects.all()
    permission_classes = [permissions.AllowAny]
