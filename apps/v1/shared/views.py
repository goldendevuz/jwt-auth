import string
import random

from django.urls import reverse
from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework.views import APIView
from rest_framework import status


@api_view(['POST'])
def test(request):
    return Response({"message": "Hello, world!"})

@api_view(['GET'])
def api_root(request):
    urls = {
        'admin': '/admin/',
        'users': '/user/',
        'posts': '/post/',
        'test-login': reverse('test'),
    }
    return Response(urls)

@api_view(['GET'])
def api_users(request):
    urls = {
        'login': '/user/login/',
        'login/refresh': '/user/login/refresh/',
        'logout': '/user/logout/',
        'signup': '/user/signup/',
        'verify': '/user/verify/',
        'new-verify': '/user/new-verify/',
        'change-user': '/user/change-user/',
        'change-user-photo': '/user/change-user-photo/',
        'forgot-password': '/user/forgot-password/',
        'reset-password': '/user/reset-password/',
    }
    return Response(urls)

class PasswordGeneratorView(APIView):
    def get(self, request):
        length = int(request.query_params.get('length', 12))
        include_upper = request.query_params.get('upper', 'true') == 'true'
        include_lower = request.query_params.get('lower', 'true') == 'true'
        include_digits = request.query_params.get('digits', 'true') == 'true'
        include_symbols = request.query_params.get('symbols', 'false') == 'true'

        if length < 4:
            return Response({"error": "Minimum password length is 4."}, status=status.HTTP_400_BAD_REQUEST)

        charset = ''
        if include_upper:
            charset += string.ascii_uppercase
        if include_lower:
            charset += string.ascii_lowercase
        if include_digits:
            charset += string.digits
        if include_symbols:
            charset += string.punctuation

        if not charset:
            return Response({"error": "No character sets selected."}, status=status.HTTP_400_BAD_REQUEST)

        password = ''.join(random.SystemRandom().choice(charset) for _ in range(length))

        return Response({
            "success": True,
            "password": password
        }, status=status.HTTP_200_OK)