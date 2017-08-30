from django.contrib.auth.models import User

from rest_framework import serializers

from auth.models import UserProfile


class UserSerializer(serializers.ModelSerializer):

    # Can never see password
    password = serializers.CharField(write_only=True)

    # Make these fields required
    first_name = serializers.CharField(max_length=150)
    last_name = serializers.CharField(max_length=150)
    email = serializers.EmailField() # TODO make unique

    # Make these fields read only
    is_active = serializers.BooleanField(read_only=True)
    is_staff = serializers.BooleanField(read_only=True)
    is_superuser = serializers.BooleanField(read_only=True)

    last_login = serializers.DateTimeField(read_only=True)
    date_joined = serializers.DateTimeField(read_only=True)

    class Meta:
        model = User
        fields = (
            'id',
            'username',
            'password',
            'first_name',
            'last_name',
            'email',
            'is_active',
            'is_staff',
            'is_superuser',
            'last_login',
            'date_joined'
        )


    def create(self, validated_data):
        user = User(
            username=validated_data['username'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            email=validated_data['email']
        )

        user.set_password(validated_data['password'])
        user.save()
        return user

    # TODO create update method
    #TODO add email and password validators


class UserProfileSerializer(serializers.ModelSerializer):
    user = UserSerializer()

    class Meta:
        model = UserProfile
        fields = ('id', 'user', 'dob', 'car', 'num_seats')

    def create(self, validated_data):
        user_data = validated_data.pop('user')
        user = UserSerializer().create(user_data)
        return UserProfile.objects.create(user=user, **validated_data)

    # TODO write update method
    def update(self, instance, validated_data):
        pass
