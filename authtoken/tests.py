from django.urls import reverse

from rest_framework import status
from rest_framework.test import (
    APIRequestFactory,
    APIClient,
    APITestCase
)

from auth.serializers import UserProfileSerializer


class AuthTokenTests(APITestCase):
    _django_user_dict = {
        'username': 'TEST',
        'password': 'password',
        'first_name': 'TEST',
        'last_name': 'TEST',
        'email': 'TEST@test.com'
    }

    @classmethod
    def setUp(cls):
        """Sets up required database information for running tests.
        """
        cls.factory = APIRequestFactory()
        cls.client = APIClient()

        # Create a User and UserProfile object
        user_profile = UserProfileSerializer(data={
            'user': cls._django_user_dict,
            'dob': '1995-01-01'
        })

        if not user_profile.is_valid():
            raise AssertionError(user_profile.errors)
        cls.user_profile = user_profile.save()

    def _assert_response_equal_status(self, response, code=status.HTTP_200_OK):
        """Asserts that the response status is equal to `code`"""
        self.assertEqual(response.status_code, code, msg=response.content)

    # def _login(self, username=None, password=None):
    #     """
    #     Login by username and password. If `username` or `password` is not suppiled,
    #     assume the class member `_django_user`.
    #     """
    #     if not username:
    #         username = self._django_user_dict['username']
    #     if not password:
    #         password = self._django_user_dict['password']

    #     self.client.login(username=username, password=password)

    def test_obtain_token_view(self):
        """Tests getting token results in HTTP 200 OK and response data
        has key `token`.
        """
        response = self.client.post(reverse('authtoken:obtain-auth-token'),
                                    {
                                        'username': self._django_user_dict['username'],
                                        'password': self._django_user_dict['password']
                                    },
                                    format='json')
        self._assert_response_equal_status(response, status.HTTP_200_OK)
        self.assertIn('token', response.data)

    def test_autheticate_inactive_user(self):
        """Tests authenticating while a user is not active will raise AuthenticationFailed and
        results in HTTP 403 FORBIDDEN
        """
        # Get user's token. If user is inactive, the token cannot be generated.
        token = self.client.post(reverse('authtoken:obtain-auth-token'),
                                 {
                                     'username': self._django_user_dict['username'],
                                     'password': self._django_user_dict['password']
                                 },
                                 format='json').data['token']

        # Set user to inactive
        self.user_profile.user.is_active = False
        self.user_profile.user.save()

        self.assertFalse(self.user_profile.user.is_active)

        self.client.credentials(HTTP_AUTHORIZATION=b'Bearer ' + token)
        response = self.client.get(reverse('rest-auth:users-detail',
                                           kwargs={'pk': self.user_profile.id}))
        self._assert_response_equal_status(response, code=status.HTTP_403_FORBIDDEN)
