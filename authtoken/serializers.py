from django.core.exceptions import ValidationError
from django.contrib.auth import authenticate
from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers

from authtoken.authentication import validate_user


class AuthTokenSerializer(serializers.Serializer):
    username = serializers.CharField(label=_('Username'))
    password = serializers.CharField(
        label=_('Password'),
        style={'input_type': 'password'},
        trim_whitespace=False
    )

    def validate(self, attrs):
        username = attrs.get('username')
        password = attrs.get('password')

        if username and password:
            user = authenticate(username=username, password=password)

            if user:
                try:
                    validate_user(user)
                except ValidationError as exc:
                    raise serializers.ValidationError(_(str(exc)), code='authorization')
            else:
                msg = _('Unable to log in with provided credentials.')
                raise serializers.ValidationError(msg, code='authorization')
        else:
            msg = _('Must include `username` and `password`.')
            raise serializers.ValidationError(msg, code='authorization')

        attrs['user'] = user
        return attrs
