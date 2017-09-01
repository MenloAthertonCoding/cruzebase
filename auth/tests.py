from datetime import date
import json

from django.urls import reverse
from django.contrib.auth.models import User

from rest_framework import status
from rest_framework.test import APIRequestFactory, APIClient, APITestCase

from auth.views import UserProfileViewSet
from auth.models import UserProfile


class UserProfileTests(APITestCase):

    @classmethod
    def setUp(cls):
        """Sets up required database information for running tests"""
        cls.factory = APIRequestFactory()
        cls.client = APIClient()

        # Create a User and UserProfile object
        _user = User(**{
            'username':'Test',
            'first_name': 'Test',
            'last_name': 'Test',
            'email': 'test@test.com'
            })
        _user.set_password('password')
        _user.save()
        cls.user_profile = UserProfile.objects.create(user=_user, dob='1995-01-01')

    def _assert_response_equal_status(self, response, code=status.HTTP_200_OK):
        """Asserts that the response status is equal to `code`"""
        self.assertEqual(response.status_code, code, msg=response.content)

    def test_create_user_profile(self):
        """Tests creating user results in db creation and HTTP 201 CREATED"""
        user_prof_data = {
            'dob': '1995-01-01',
            'user': {
                'username':'Test2',
                'password':'new_password',
                'first_name': 'Test',
                'last_name': 'Test',
                'email': 'test@test.com'
            }
        }

        response = self.client.post(reverse('rest-auth:users-list'), user_prof_data, format='json')
        self._assert_response_equal_status(response, status.HTTP_201_CREATED)
        self.assertGreater(UserProfile.objects.count(), 1)

    def test_create_user_profile_no_required_fields(self):
        """
        Tests creating user without required `first_name`, `last_name`, and `email`
        results in HTTP 400 BAD REQUEST
        """
        user_prof_data = {
            'dob': '1995-01-01',
            'user': {
                'username':'Test3',
                'password':'new_password'
            }
        }

        response = self.client.post(reverse('rest-auth:users-list'), user_prof_data, format='json')
        self._assert_response_equal_status(response, status.HTTP_400_BAD_REQUEST)

    def test_update_user_profile(self):
        """Tests updating user results in db update and HTTP 200 OK"""
        user_prof_data = {
            'dob': '1897-01-01',
            'user': {
                'username':'Piply',
                'password':'updated_password',
                'first_name': 'Test4',
                'last_name': 'Test5',
                'email': 'test2@test.com'
            }
        }
        response = self.client.put(reverse('rest-auth:users-detail', kwargs={'pk': 1}),
                                   user_prof_data, format='json')
        self._assert_response_equal_status(response)

        user_password_cached = self.user_profile.user.password

        # Update user_profile after updating it server side and assert
        # dobs are not equivalent
        self.user_profile = UserProfile.objects.get(pk=1)
        year, month, day = user_prof_data['dob'].split('-')
        self.assertEqual(self.user_profile.dob, date(int(year), int(month), int(day)))

        # Assert that password has been changed
        self.assertNotEqual(self.user_profile.user.password, user_password_cached)

    def test_update_partial_user_profile(self):
        """Tests partially updating user results in db update and HTTP 200 OK"""
        user_prof_data = {
            'user': {
                'password': 'partial_update_password',
                'last_name': 'Test0'
            }
        }
        response = self.client.patch(reverse('rest-auth:users-detail', kwargs={'pk': 1}),
                                     user_prof_data, format='json')
        self._assert_response_equal_status(response)

        user_password_cached = self.user_profile.user.password

        # Update user_profile after partially updating it server
        # side and assert last name are equivalent
        self.user_profile = UserProfile.objects.get(pk=self.user_profile.pk)
        self.assertEqual(self.user_profile.user.last_name, user_prof_data['user']['last_name'])

        # Assert that password has been changed
        self.assertNotEqual(self.user_profile.user.password, user_password_cached)

    def test_get_user_profile_list(self):
        """Tests user profile list returns HTTP 200 OK"""
        response = self.client.get(reverse('rest-auth:users-list'))
        self._assert_response_equal_status(response)

    def test_user_profile_password_write_only(self):
        """Tests users password is write only (cannot be read)"""
        response = self.client.get(reverse('rest-auth:users-list'))
        for user_profile in json.loads(response.content.decode())['results']:
            self.assertNotIn('password', user_profile['user'])


    def test_get_user_profile_detail(self):
        """Tests user profile list returns HTTP 200 OK"""
        response = self.client.get(reverse('rest-auth:users-detail', kwargs={'pk': 1}))
        self._assert_response_equal_status(response)
