from rest_framework.views import APIView
from rest_framework.response import Response

from jwt import token_factory

from authtoken.serializers import AuthTokenSerializer
from authtoken.settings import api_settings, secret_key
from authtoken.authentication import get_token_instance

class ObtainAuthToken(APIView):
    serializer_class = AuthTokenSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user_profile = serializer.validated_data['user'].user_profile

        token = get_token_instance(user_profile)

        return Response({'token': token.build(
            secret_key(),
            api_settings.TOKEN_VERIFICATION_ALGORITHM_INSTANCE
        )})
