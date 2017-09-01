from django.contrib.auth.models import User
from django.utils.translation import ugettext as _

from rest_framework import serializers

from auth.models import UserProfile


class UserSerializer(serializers.ModelSerializer):
    """
    Serializer class used to validate a Django User.

    Sets `is_active`, `is_staff`, `is_superuser`, `last_login`, and `date_joined` fields
    to `read_only`, `password` field to `write_only`, and `first_name`, `last_name`, and `email`
    to `required`. Also sets `email` to be unique.abs

    Validates that password is of a certain length and email has a whitelisted domain address.
    Salts and hashes a clear text password
    """

    # Make these fields required
    first_name = serializers.CharField(max_length=150)
    last_name = serializers.CharField(max_length=150)
    email = serializers.EmailField() # TODO make unique

    class Meta:
        """Metadata class. Tells DRF what's gucci."""
        model = User

        # Exclude these from serializers
        exclude = ('groups', 'user_permissions')

        read_only_fields = (
            'is_active',
            'is_staff',
            'is_superuser',
            'last_login',
            'date_joined'
        )

        # Make password write only
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        """
        Overrides create method. Saves the `validated_data` to a Django `User` object.
        Salts and hashes a clear text password.
        """
        user = User(
            username=validated_data['username'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            email=validated_data['email']
        )

        user.set_password(validated_data['password'])
        user.save()
        return user

    def update(self, instance, validated_data):
        """Overrides update method. Updates Django `User` object with `validated_data`."""
        for k in validated_data:
            if getattr(instance, k) is not 'password':
                # Use QuerySet.update to update mutiple objects
                setattr(instance, k, validated_data[k])
        if 'password' in validated_data:
            instance.set_password(validated_data['password'])
        instance.save()
        return instance

    def validate_password(self, value):
        """Validates that clear text password `value` is more than 8 characters long"""
        # TODO Add PASS_LENGTH to SETTINGS
        val_len = 8
        if len(value) < val_len:
            raise serializers.ValidationError(_('Password must be at least\
            {0} characters long.'.format(val_len)))
        return value

    def validate_email(self, value):
        """Validates that email `value` has whitelisted domain name address"""
        # Automatically validates that `value` is a valid email adress (parent validator)
        # TODO Implement method
        return value


class UserProfileSerializer(serializers.ModelSerializer):
    """
    Serializer class used to validate a custom User object that has a `OneToOne` relatioship with
    the default Django user.

    Creates and updates a `UserProfile` and Django `User` object
    """

    user = UserSerializer()

    class Meta:
        """Metadata class. Tells DRF what's gucci."""
        model = UserProfile
        fields = '__all__'

    def create(self, validated_data):
        """
        Overrides create method. Saves the `validated_data` to a `UserProfile` object
        and a Django `User` object. The two objects have a `OneToOne` relationship.
        """
        user_data = validated_data.pop('user')
        user = UserSerializer().create(user_data)
        return UserProfile.objects.create(user=user, **validated_data)

    def update(self, instance, validated_data):
        """Overrides update method. Updates `UserProfile` and Django `User` object with `validated_data`."""
        user_data = validated_data.pop('user')
        for k in validated_data:
            setattr(instance, k, validated_data[k]) # Use QuerySet.update to update mutiple objects
        instance.save()
        UserSerializer().update(instance.user, user_data) # Could raise `DoesNotExist` if instance.user is undefined
        return instance
