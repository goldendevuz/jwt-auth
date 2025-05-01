import json
import os
import shutil
import inspect
from types import SimpleNamespace
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APITestCase
from icecream import ic

from apps.v1.users.models import NEW, UserConfirmation
from core import settings

User = get_user_model()
USERNAME_PHONE_EMAIL = "yunusovabdulmajid@gmail.com"

class UserAPITestCase(APITestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.tests_root_dir = os.path.join(settings.BASE_DIR, 'playground', 'test_outputs')


        if os.path.exists(cls.tests_root_dir):
            shutil.rmtree(cls.tests_root_dir)

        os.makedirs(cls.tests_root_dir, exist_ok=True)

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(cls.tests_root_dir):
            shutil.rmtree(cls.tests_root_dir)
        super().tearDownClass()

    def save_response_data(self, response):
        test_name = inspect.stack()[1].function
        status_code = str(response.status_code)

        os.makedirs(self.tests_root_dir, exist_ok=True)
        target_dir = os.path.join(self.tests_root_dir, status_code)
        os.makedirs(target_dir, exist_ok=True)

        file_path = os.path.join(target_dir, f"{test_name}.json")
        with open(file_path, 'w') as f:
            json.dump(response.data, f, indent=4)


    def signup(self, email=USERNAME_PHONE_EMAIL):
        """Helper to signup a user and return response + parsed object"""
        url = reverse('signup')
        data = {"username_phone_email": email}
        response = self.client.post(url, data)
        self.save_response_data(response)
        obj = SimpleNamespace(**response.data)
        return response, obj

    def verify_signup(self, email=USERNAME_PHONE_EMAIL):
        """Helper to fetch the 4-digit code and verify signup"""
        confirmation = UserConfirmation.objects.get(verify_value=email)
        verify_url = reverse('verify')
        verify_data = {
            "code": confirmation.code
        }
        response = self.client.post(verify_url, verify_data)
        self.save_response_data(response)
        return response

    def authenticate(self, email=USERNAME_PHONE_EMAIL):
        """Sign up, verify, and authenticate the test client"""
        response, obj = self.signup(email=email)
        self.verify_signup(email=email)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {obj.access_token}")
        return obj

    def test_create_password(self):
        url = reverse('generate-password')
        response = self.client.get(url)
        self.save_response_data(response)
        self.assertEqual(response.status_code, 200)
        obj = SimpleNamespace(**response.data)
        self.assertTrue(len(obj.password) >= 8)

    def test_signup(self):
        response, obj = self.signup()
        self.assertEqual(response.status_code, 201)
        self.assertIn('access_token', response.data)
        self.assertIn('refresh_token', response.data)
        self.assertEqual(obj.auth_status, NEW)


    def test_authenticated_endpoint(self):
        """Example test using authenticated client"""
        self.authenticate()
        url = reverse('test-login')
        response = self.client.get(url)
        self.save_response_data(response)
        self.assertEqual(response.status_code, 200)

    def test_authenticated_verify_with_jwt(self):
        """Test verification after signing up and authenticating with JWT"""
        # Step 1: Signup and authenticate (including JWT token)
        self.authenticate()

        # Step 2: Get the verification code from the UserConfirmation model
        confirmation = UserConfirmation.objects.get(verify_value=USERNAME_PHONE_EMAIL)
        code = confirmation.code

        # Step 3: Call the 'verify' endpoint with the code and authenticated JWT
        verify_url = reverse('verify')
        verify_data = {"code": code}
        response = self.client.post(verify_url, verify_data)

        # Step 4: Assert success (status 200)
        self.save_response_data(response)
        self.assertEqual(response.status_code, 200)


# def test_login(self):
#     url = reverse('test-login')
#     response = self.client.get(url)

#     self.save_response_data(response)

#     self.assertEqual(response.status_code, 200)
#     self.assertEqual({"message": "Hello, world!"}, result)
