from rest_framework.views import APIView
from rest_framework.response import Response

from jwt.components import HS256HeaderComponent
from jwt.algorithms import HMACAlgorithm
from jwt import token_factory

from authtoken.serializers import AuthTokenSerializer
from authtoken.jwtcomp import PayloadComponent


class ObtainAuthToken(APIView):
    serializer_class = AuthTokenSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user_profile = serializer.validated_data['user'].user_profile

        token = token_factory(
            HS256HeaderComponent,
            PayloadComponent,
            {
                'payload': {'aud': user_profile.id}
            }
        )

        return Response({'token': token.sign('secret', # TODO get real secret
                                             HMACAlgorithm(HMACAlgorithm.SHA256)).build()})
