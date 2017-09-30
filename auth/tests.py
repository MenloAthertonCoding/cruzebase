from datetime import date, timedelta
import json

from django.urls import reverse
from django.utils import timezone

from rest_framework import status
from rest_framework.test import (
    APIClient,
    APITestCase,
    APIRequestFactory
)

from auth.models import UserProfile
from auth.serializers import UserProfileSerializer
from auth.permissions import IsNotSuspended


class UserProfileAuthenticationTests:
    @classmethod
    def setUp(cls):
        """Sets up required database information for running tests"""
        cls.client = APIClient()
        cls.factory = APIRequestFactory()

        # Create a User and UserProfile object
        user_profile = UserProfileSerializer(data={
            'user': cls._get_user_profile_data().pop('user'),
            'dob': '1995-01-01'
        })

        if not user_profile.is_valid():
            raise AssertionError(user_profile.errors)
        cls.user_profile = user_profile.save()

        # Create superuser (admin) user
        super_user = UserProfileSerializer(data={
            'user': cls._get_user_profile_data(username='admin',
                                               email='admin@admin.com').pop('user'),
            'dob': '1995-01-01'
        })

        if not super_user.is_valid():
            raise AssertionError(super_user.errors)
        cls.super_user = super_user.save()

        # Must save it manually instead of passing this value into .save() as
        # kwargs as DRF does not support relational mappings.
        cls.super_user.user.is_superuser = True
        cls.super_user.user.save()

    @classmethod
    def _update_profile_user(cls):
        """Update `user_profile` after it being updated server side"""
        cls.user_profile = UserProfile.objects.get(pk=cls.user_profile.pk)

    def _assert_response_equal_status(self, response, code=status.HTTP_200_OK):
        """Asserts that the response status is equal to `code`"""
        self.assertEqual(response.status_code, code, msg=response.content)

    @classmethod
    def _get_user_profile_data(cls, dob='1995-01-01', username='TEST', password='password',
                               first_name='TEST', last_name='TEST', email='TEST@test.com'):
        """Returns a `dict` full of `UserProfile` information"""
        return {
            'dob': dob,
            'user': {
                'username': username,
                'password': password,
                'first_name': first_name,
                'last_name': last_name,
                'email': email
            }
        }

    def _login_su(self):
        """Login superuser through APIClient"""
        self._login(self.super_user.user.username)

    def _login_pu(self):
        """Login user profile through APIClient"""
        self._login()

    def _login(self, username=None, password=None):
        """
        Children classes must implement ._login()
        """
        raise NotImplementedError("._login() must be overridden.")

    def _logout(self):
        """
        Children classes must implement ._logout()
        """
        raise NotImplementedError("._logout() must be overridden.")

    def test_create_user_profile(self):
        """Tests creating user results in db creation and HTTP 201 CREATED"""
        response = self.client.post(reverse('rest-auth:users-list'),
                                    self._get_user_profile_data(username='TEST_CREATE_USER',
                                                                email='TEST_CREATE_USER@test.com'),
                                    format='json')
        self._assert_response_equal_status(response, status.HTTP_201_CREATED)
        self.assertGreater(UserProfile.objects.count(), 1)

    def test_create_user_profile_no_required_field(self):
        """
        Tests creating user without required `first_name`, `last_name`, and `email`
        results in HTTP 400 BAD REQUEST
        """
        user_profile_data = {
            'dob': '1995-01-01',
            'user': {
                'username':'TEST3',
                'password':'password'
            }
        }

        response = self.client.post(reverse('rest-auth:users-list'),
                                    user_profile_data, format='json')
        self._assert_response_equal_status(response, status.HTTP_400_BAD_REQUEST)

    def test_create_user_profile_duplicate_email(self):
        """Tests creating user with a duplicate email results in HTTP 400 BAD REQUEST"""
        response = self.client.post(reverse('rest-auth:users-list'),
                                    self._get_user_profile_data(
                                        username='TEST_CREATE_USER_DUP_EMAIL'
                                    ), format='json')
        self._assert_response_equal_status(response, status.HTTP_400_BAD_REQUEST)

    def test_update_user_profile(self):
        """Tests updating user results in db update and HTTP 200 OK"""
        user_profile_data = self._get_user_profile_data(
            dob='1897-01-01',
            username='TEST_UPDATE_USER',
            password='updated_password',
            first_name='TEST_UPDATED_FIRST_NAME',
            last_name='TEST_UPDATED_LAST_NAME',
            email='TEST_UPDATED_EMAIL@test.com'
        )
        self._login_pu()
        response = self.client.put(reverse('rest-auth:users-detail',
                                           kwargs={'pk': self.user_profile.id}),
                                   user_profile_data, format='json')
        self._logout()
        self._assert_response_equal_status(response)

        user_password_cached = self.user_profile.user.password

        # Update user_profile after updating it server side and assert
        # dobs are not equivalent
        self._update_profile_user()
        year, month, day = user_profile_data['dob'].split('-')
        self.assertEqual(self.user_profile.dob, date(int(year), int(month), int(day)))

        # Assert that password has been changed
        self.assertNotEqual(self.user_profile.user.password, user_password_cached)

    def test_update_user_profile_admin(self):
        """Tests updating user by an admin results in db update and HTTP 200 OK"""
        user_profile_data = self._get_user_profile_data(
            dob='1897-01-01',
            username='TEST_UPDATE_USER',
            password='updated_password',
            first_name='TEST_UPDATED_FIRST_NAME',
            last_name='TEST_UPDATED_LAST_NAME',
            email='TEST_UPDATED_EMAIL@test.com'
        )
        self._login_su()
        response = self.client.put(reverse('rest-auth:users-detail',
                                           kwargs={'pk': self.user_profile.id}),
                                   user_profile_data, format='json')
        self._logout()
        self._assert_response_equal_status(response)

        user_password_cached = self.user_profile.user.password

        # Update user_profile after updating it server side and assert
        # dobs are not equivalent
        self._update_profile_user()
        year, month, day = user_profile_data['dob'].split('-')
        self.assertEqual(self.user_profile.dob, date(int(year), int(month), int(day)))

        # Assert that password has been changed
        self.assertNotEqual(self.user_profile.user.password, user_password_cached)

    def test_update_user_profile_no_creds(self):
        """Tests updating user without credentials results in HTP 403 FORBIDDEN"""
        user_profile_data = self._get_user_profile_data(
            dob='1897-01-01',
            username='TEST_UPDATE_USER',
            password='updated_password',
            first_name='TEST_UPDATED_FIRST_NAME',
            last_name='TEST_UPDATED_LAST_NAME',
            email='TEST_UPDATED_EMAIL@test.com'
        )
        response = self.client.put(reverse('rest-auth:users-detail',
                                           kwargs={'pk': self.user_profile.id}),
                                   user_profile_data, format='json')
        self._assert_response_equal_status(response, status.HTTP_403_FORBIDDEN)

    def test_update_partial_user_profile(self):
        """Tests partially updating user results in db update and HTTP 200 OK"""
        user_profile_data = {
            'user': {
                'password': 'partial_update_password',
                'last_name': 'TEST_PARTIAL_UPDATED_LAST_NAME'
            }
        }
        self._login_pu()
        response = self.client.patch(reverse('rest-auth:users-detail',
                                             kwargs={'pk': self.user_profile.id}),
                                     user_profile_data, format='json')
        self._logout()
        self._assert_response_equal_status(response)

        user_password_cached = self.user_profile.user.password

        # Update user_profile after partially updating it server
        # side and assert last name are equivalent
        self._update_profile_user()
        self.assertEqual(self.user_profile.user.last_name,
                         user_profile_data.pop('user')['last_name'])

        # Assert that password has been changed
        self.assertNotEqual(self.user_profile.user.password, user_password_cached)

    def test_update_partial_user_profile_no_creds(self):
        """Tests partially updating user without credentials results in HTTP 403 FORBIDDEN"""
        user_profile_data = {
            'user': {
                'password': 'partial_update_password',
                'last_name': 'TEST_PARTIAL_UPDATED_LAST_NAME_NO_CREDS'
            }
        }
        response = self.client.patch(reverse('rest-auth:users-detail',
                                             kwargs={'pk': self.user_profile.id}),
                                     user_profile_data, format='json')
        self._assert_response_equal_status(response, status.HTTP_403_FORBIDDEN)

    def test_update_partial_user_profile_admin(self):
        """Tests partially updating user by an admin results in db update and HTTP 200 OK"""
        user_profile_data = {
            'user': {
                'password': 'partial_update_password',
                'last_name': 'TEST_PARTIAL_UPDATED_LAST_NAME_ADMIN'
            }
        }
        self._login_su()
        response = self.client.patch(reverse('rest-auth:users-detail',
                                             kwargs={'pk': self.user_profile.id}),
                                     user_profile_data, format='json')
        self._logout()
        self._assert_response_equal_status(response)

        user_password_cached = self.user_profile.user.password

        # Update user_profile after partially updating it server
        # side and assert last name are equivalent
        self._update_profile_user()
        self.assertEqual(self.user_profile.user.last_name,
                         user_profile_data.pop('user')['last_name'])

        # Assert that password has been changed
        self.assertNotEqual(self.user_profile.user.password, user_password_cached)

    def test_get_user_profile_list(self):
        """Tests user profile list returns HTTP 200 OK"""
        response = self.client.get(reverse('rest-auth:users-list'))
        self._assert_response_equal_status(response)

    def test_user_profile_password_write_only(self):
        """Tests users password is write only (cannot be read)"""
        response = self.client.get(reverse('rest-auth:users-list'))
        for user_profile in json.loads(response.content.decode()).pop('results'):
            self.assertNotIn('password', user_profile.pop('user'))


    def test_get_user_profile_detail(self):
        """Tests user profile detail returns HTTP 200 OK"""
        response = self.client.get(reverse('rest-auth:users-detail',
                                           kwargs={'pk': self.user_profile.id}))
        self._assert_response_equal_status(response)

    def test_destroy_user_profile_detail(self):
        """Tests deleting user profile returns HTTP 200 OK"""
        self._login_pu()
        response = self.client.delete(reverse('rest-auth:users-detail',
                                              kwargs={'pk': self.user_profile.id}))
        self._logout()
        self._assert_response_equal_status(response)

        # Update user profile and assert that the Django User object is not active
        self._update_profile_user()
        self.assertEqual(self.user_profile.user.is_active, False)

    def test_destroy_user_profile_detail_admin(self):
        """Tests deleting user profile when logged in as an admin returns HTTP 200 OK"""
        self._login_su()
        response = self.client.delete(reverse('rest-auth:users-detail',
                                              kwargs={'pk': self.user_profile.id}))
        self._logout()
        self._assert_response_equal_status(response)

        # Update user profile and assert that the Django User object is not active
        self._update_profile_user()
        self.assertEqual(self.user_profile.user.is_active, False)

    def test_destroy_user_profile_detail_no_creds(self):
        """Tests deleting user profile without credentials returns HTTP 403 FORBIDDEN"""
        response = self.client.delete(reverse('rest-auth:users-detail',
                                              kwargs={'pk': self.user_profile.id}))
        self._assert_response_equal_status(response, status.HTTP_403_FORBIDDEN)

    def test_suspended_user(self):
        """Tests deleting user profile without credentials returns HTTP 403 FORBIDDEN"""
        # Ensure that user is not authenticated to update profile data when
        # suspended
        self.user_profile.suspended_until = timezone.now() + timedelta(seconds=30)
        self.user_profile.save()

        request = self.factory.put(reverse('rest-auth:users-detail',
                                           kwargs={'pk': self.user_profile.id}))
        request.user = self.user_profile.user

        has_permission = IsNotSuspended().has_permission(request, view=None)
        self.assertFalse(has_permission)

        # Ensure that user is authenticated to update profile data and last_suspension
        # attribute is set when suspension ends
        self.user_profile.suspended_until = timezone.now() - timedelta(seconds=30)
        self.user_profile.save()

        has_permission = IsNotSuspended().has_permission(request, view=None)

        self.assertTrue(has_permission)
        self._update_profile_user()

        self.assertEqual(self.user_profile.suspended_until, None)
        self.assertNotEqual(self.user_profile.last_suspension, None)


# Parent classes must be in this order
class UserProfileSessionAuthenticationTests(UserProfileAuthenticationTests, APITestCase):

    def _login(self, username=None, password=None):
        """
        Login by username and password. If `username` or `password` is not supplied,
        assume the values from `.self._get_user_profile_data()`.
        """
        user_data = self._get_user_profile_data().pop('user')
        if not username:
            username = user_data['username']
        if not password:
            password = user_data['password']

        self.client.login(username=username, password=password)

    def _logout(self):
        self.client.logout()


class UserProfileJSONWebTokenAuthenticationTests(UserProfileAuthenticationTests, APITestCase):

    def _login(self, username=None, password=None):
        """
        Login by username and password. If `username` or `password` is not supplied,
        assume the values from `.self._get_user_profile_data()`.
        """
        user_data = self._get_user_profile_data().pop('user')
        if not username:
            username = user_data['username']
        if not password:
            password = user_data['password']

        token = self.client.post(reverse('authtoken:obtain-auth-token'),
                                 {
                                     'username': username,
                                     'password': password
                                 },
                                 format='json').data['token']

        self.client.credentials(HTTP_AUTHORIZATION=b'Bearer ' + token)

    def _logout(self):
        self.client.credentials()
