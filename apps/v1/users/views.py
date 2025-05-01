import random
import string
from django.core.exceptions import ObjectDoesNotExist
from django.utils.timezone import datetime
from rest_framework import permissions, status
from rest_framework.exceptions import ValidationError, NotFound
from rest_framework.generics import CreateAPIView, UpdateAPIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework.decorators import api_view

from apps.v1.shared.utils.response import success_response
from apps.v1.shared.utility import send_email, check_username_phone_email, send_phone_code
from .serializers import SignUpSerializer, ChangeUserInformation, ChangeUserPhotoSerializer, LoginSerializer, \
    LoginRefreshSerializer, LogoutSerializer, ResetPasswordSerializer
from .models import User, CODE_VERIFIED, NEW, VIA_EMAIL, VIA_PHONE, UserConfirmation


class CreateUserView(CreateAPIView):
    queryset = User.objects.all()
    permission_classes = (permissions.AllowAny, )
    serializer_class = SignUpSerializer


class VerifyAPIView(APIView):
    permission_classes = (IsAuthenticated, )

    def post(self, request, *args, **kwargs):
        user = self.request.user             # user ->
        code = self.request.data.get('code') # 4083
        # if user.auth_status != NEW:
        #     data = {
        #         "auth_status": user.auth_status,
        #         "message": "Siz allaqachon tasdiqlangan hisobga egasiz"
        #     }
        #     raise ValidationError(data)

        self.check_verify(user, code)
        return Response(
            data={
                "auth_status": user.auth_status,
                "access_token": user.token()['access_token'],
                "refresh": user.token()['refresh_token']
            }
        )

    @staticmethod
    def check_verify(user, code):       # 12:03 -> 12:05 => expiration_time=12:05   12:04
        verifies = user.verify_codes.filter(expiration_time__gte=datetime.now(), code=code, is_confirmed=False)
        # ic(verifies)
        # ic(user.__dict__)
        # ic(code)
        # ic(UserConfirmation.objects.filter(user_id=user.id, code=code).first().__dict__)
        usr = UserConfirmation.objects.filter(user_id=user.id, code=code).first()
        if not verifies.exists():
            data = {
                "message": "Tasdiqlash kodingiz xato yoki eskirgan"
            }
            raise ValidationError(data)
        else:
            verifies.update(is_confirmed=True)
        if user.auth_status == NEW:
            user.auth_status = CODE_VERIFIED
            if usr.verify_type == VIA_PHONE:
                user.phone_number = usr.verify_value
            elif usr.verify_type == VIA_EMAIL:
                user.email = usr.verify_value
            user.save()
        return True


class GetNewVerification(APIView):
    permission_classes = [IsAuthenticated, ]

    def get(self, request, *args, **kwargs):
        user = self.request.user
        # if user.auth_status != NEW:
        #     data = {
        #         "success": True,
        #         "auth_status": user.auth_status,
        #         "message": "Siz allaqachon tasdiqlangan hisobga egasiz"
        #     }
        #     raise ValidationError(data)
        # ic(request.user.__dict__)
        self.check_verification(user)
        if user.auth_type == VIA_EMAIL:
            code = user.create_verify_code(VIA_EMAIL)
            send_email(user.email, code)
        elif user.auth_type == VIA_PHONE:
            code = user.create_verify_code(VIA_PHONE)
            send_phone_code(user.phone_number, code)
        else:
            data = {
                "message": "Email yoki telefon raqami notogri"
            }
            raise ValidationError(data)

        return Response(
            {
                "success": True,
                "message": "Tasdiqlash kodingiz qaytadan jo'natildi."
            }
        )

    @staticmethod
    def check_verification(user):
        verifies = user.verify_codes.filter(expiration_time__gte=datetime.now(), is_confirmed=False)
        if verifies.exists():
            data = {
                "message": "Kodingiz hali ishlatish uchun yaroqli. Biroz kutib turing"
            }
            raise ValidationError(data)


class UpdateUserInformationView(UpdateAPIView):
    permission_classes = [IsAuthenticated, ]
    serializer_class = ChangeUserInformation
    http_method_names = ('patch',)

    def get_object(self):
        return self.request.user

    def partial_update(self, request, *args, **kwargs):
        if not request.data:
            return Response({
                'success': False,
                'message': 'No data provided for update.',
            }, status=status.HTTP_400_BAD_REQUEST)

        super(UpdateUserInformationView, self).partial_update(request, *args, **kwargs)
        
        data = {
            'success': True,
            "message": "User updated successfully",
            'auth_status': self.request.user.auth_status,
        }
        return Response(data, status=status.HTTP_200_OK)


class ChangeUserPhotoView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request, *args, **kwargs):
        serializer = ChangeUserPhotoSerializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            serializer.update(user, serializer.validated_data)
            return success_response("Rasm muvaffaqiyatli o'zgartirildi", status_code=status.HTTP_200_OK)
        
        # Let your custom exception handler deal with it
        raise ValidationError(serializer.errors)


class LoginView(TokenObtainPairView):
    serializer_class = LoginSerializer


class LoginRefreshView(TokenRefreshView):
    serializer_class = LoginRefreshSerializer


class LogOutView(APIView):
    serializer_class = LogoutSerializer
    permission_classes = [IsAuthenticated, ]

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=self.request.data)
        serializer.is_valid(raise_exception=True)
        try:
            refresh_token = self.request.data['refresh']
            token = RefreshToken(refresh_token)
            token.blacklist()
            data = {
                'success': True,
                'message': "You are loggout out"
            }
            return Response(data, status=205)
        except TokenError:
            data = {
                "message": "Token is invalid or expired"
            }
            raise ValidationError(data)


class ResetPasswordView(APIView):
    permission_classes = [AllowAny]
    serializer_class = ResetPasswordSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=self.request.data)
        serializer.is_valid(raise_exception=True)
        username_phone_email = serializer.validated_data.get('username_phone_email')
        user = serializer.validated_data.get('user')
        if check_username_phone_email(username_phone_email) == 'phone':
            code = user.create_verify_code(VIA_PHONE)
            send_email(username_phone_email, code)
        elif check_username_phone_email(username_phone_email) == 'email':
            code = user.create_verify_code(VIA_EMAIL)
            send_email(username_phone_email, code)

        return Response(
            {
                "success": True,
                'message': "Tasdiqlash kodi muvaffaqiyatli yuborildi",
                "access_token": user.token()['access_token'],
                "refresh": user.token()['refresh_token'],
                "user_status": user.auth_status,
            }, status=status.HTTP_200_OK
        )

class PasswordGeneratorView(APIView):
    permission_classes = [permissions.AllowAny]
    def get(self, request):
        length = int(request.query_params.get('length', 8))
        include_upper = request.query_params.get('upper', 'true') == 'true'
        include_lower = request.query_params.get('lower', 'true') == 'true'
        include_digits = request.query_params.get('digits', 'true') == 'true'
        include_symbols = request.query_params.get('symbols', 'false') == 'true'

        if length < 8:
            return Response({"error": "Minimum password length is 8."}, status=status.HTTP_400_BAD_REQUEST)

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
        return Response({"password": password}, status=status.HTTP_200_OK)

@api_view(['GET'])
def test_login(request):
    return Response({"message": "Hello, world!"})
