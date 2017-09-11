from django.urls import reverse
from django.contrib.auth.models import User as DjangoUser

from rest_framework import status
from rest_framework.test import APIRequestFactory, APIClient, APITestCase

from auth.models import UserProfile

class AuthTokenTests(APITestCase):
    __django_user = {
        'username': 'TEST',
        'password': 'password',
        'first_name': 'TEST',
        'last_name': 'TEST',
        'email': 'TEST@test.com'
    }


    @classmethod
    def _django_user_dict(cls):
        # if not hasattr(cls, '__django_user'):
        #     raise UnboundLocalError('__django_user used before assignment')
        return cls.__django_user

    @classmethod
    def setUp(cls):
        """Sets up required database information for running tests"""
        cls.factory = APIRequestFactory()
        cls.client = APIClient()

        # Create a User and UserProfile object
        user = DjangoUser(**cls._django_user_dict())
        user.set_password(cls._django_user_dict()['password'])
        user.save()
        cls.user_profile = UserProfile.objects.create(user=user, dob='1995-01-01')

    def _assert_response_equal_status(self, response, code=status.HTTP_200_OK):
        """Asserts that the response status is equal to `code`"""
        self.assertEqual(response.status_code, code, msg=response.content)

    # def _login(self, username=None, password=None):
    #     """
    #     Login by username and password. If `username` or `password` is not suppiled,
    #     assume the class member `_django_user`.
    #     """
    #     if not username:
    #         username = self._django_user_dict()['username']
    #     if not password:
    #         password = self._django_user_dict()['password']

    #     self.client.login(username=username, password=password)

    def test_obtain_token_view(self):
        """
        Tests getting token results in HTTP 200 OK and response data
        has key `token`.
        """
        user_data = self._django_user_dict()
        response = self.client.post(reverse('authtoken:obtain-auth-token'),
                                    {
                                        'username': user_data['username'],
                                        'password': user_data['password']
                                    },
                                    format='json')
        self._assert_response_equal_status(response, status.HTTP_200_OK)
        self.assertIn('token', response.data)
