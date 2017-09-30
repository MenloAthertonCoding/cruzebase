from django.contrib.auth.models import User as DjangoUser
from django.utils.translation import ugettext as _

from rest_framework import serializers
from rest_framework.validators import UniqueValidator

from auth.models import UserProfile
from auth.settings import api_settings

class UserSerializer(serializers.ModelSerializer):
    """Serializer class used to validate a Django User.

    Sets `is_active`, `is_staff`, `is_superuser`, `last_login`, and `date_joined` fields
    to `read_only`, `password` field to `write_only`, and `first_name`, `last_name`, and `email`
    to `required`. Also sets `email` to be unique.abs

    Validates that password is of a certain length and email has a whitelisted domain address.
    Salts and hashes a clear text password
    """
    # Make these fields required
    first_name = serializers.CharField(max_length=150)
    last_name = serializers.CharField(max_length=150)
    email = serializers.EmailField(validators=[
        UniqueValidator(queryset=DjangoUser.objects.all(),
                        message=_('Email is already taken.'))])

    class Meta:
        model = DjangoUser

        # Exclude these from serializers
        exclude = ('id', 'groups', 'user_permissions')

        read_only_fields = (
            'is_active',
            'is_staff',
            'is_superuser',
            'last_login',
            'date_joined'
        )

        # Make password write only
        extra_kwargs = {'password': {'write_only': True}}

    def validate_username(self, value):
        """Validates that username of value is more than a specified length.
        """
        min_len = api_settings.USERNAME_MIN_LENGTH
        if len(value) < min_len:
            raise serializers.ValidationError(_('Username must be at least {0} characters long.'
                                                .format(min_len)))

        return value

    def validate_password(self, value):
        """Validates that clear text password is more than a specified length.
        """
        min_len = api_settings.PASSWORD_MIN_LENGTH
        if len(value) < min_len:
            raise serializers.ValidationError(_('Password must be at least {0} characters long.'
                                                .format(min_len)))

        return value

    def validate_email(self, value):
        """Validates that the email has whitelisted domain name address.
        """
        # Automatically validates that `value` is a valid email adress (parent validator)
        if api_settings.EMAIL_VALIDATE_DOMAIN:
            # TODO Implement method
            pass

        return value


class UserProfileSerializer(serializers.ModelSerializer):
    """Serializer class used to validate a custom User object that has a `OneToOne` relatioship with
    the default Django user.

    Creates and updates a `UserProfile` and Django `User` object
    """
    user = UserSerializer()

    class Meta:
        model = UserProfile
        fields = '__all__'
        read_only_fields = ('suspended_until', 'last_suspension')

    def validate_user(self, value):
        """Validates the user data is valid.
        """
        if not UserSerializer(data=value, partial=True).is_valid():
            raise serializers.ValidationError(_('User data is not valid'))
        return value

    def validate_dob(self, value):
        """Validates that date of bith is within a specified rage.
        """
        # TODO Ensure the the user is correct age
        return value

    def create(self, validated_data):
        """Overrides create method. Saves the `validated_data` to a `UserProfile` object
        and a Django `User` object. The two objects have a `OneToOne` relationship.
        """
        user_data = validated_data.pop('user')

        user = DjangoUser.objects.create_user(**user_data)
        return UserProfile.objects.create(user=user, **validated_data)

    def update(self, instance, validated_data):
        """Overrides update method. Updates `UserProfile` and Django `User` object
        with `validated_data`.
        """
        user_data = validated_data.pop('user')
        UserProfile.objects.filter(pk=instance.id).update(**validated_data)
        DjangoUser.objects.filter(pk=instance.user.id).update(**user_data)
        return instance
