from datetime import datetime

from django.db import models
from django.contrib.auth.models import User


class UserProfile(models.Model):
    """Model that extends the django user model; adds extra metadata"""
    # User one to one relationship
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='user_profile')

    # extra metadata
    dob = models.DateField(verbose_name='Date of Birth')
    car = models.BooleanField(verbose_name='Car?', default=False)
    num_seats = models.PositiveSmallIntegerField(verbose_name='Number of Car seats', null=True,
                                                 blank=True)
    last_suspension = models.DateTimeField(verbose_name='Last Suspension', blank=True, null=True)
    suspended_until = models.DateTimeField(verbose_name='Suspended until', blank=True, null=True)

    def __str__(self):
        return self.user.get_full_name()
