from django.contrib.auth import authenticate
from django.contrib.auth.models import update_last_login
from django.contrib.auth.password_validation import validate_password
from django.core.validators import FileExtensionValidator
from rest_framework.generics import get_object_or_404
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenRefreshSerializer
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken

from apps.v1.shared.utility import check_username_phone_email, send_email, send_phone_code, check_user_type
from .models import User, VIA_EMAIL, VIA_PHONE, NEW, CODE_VERIFIED, DONE, PHOTO_DONE
from django.db.models import Q
from rest_framework import serializers
from rest_framework.exceptions import ValidationError, PermissionDenied, NotFound
from icecream import ic


class SignUpSerializer(serializers.ModelSerializer):
    id = serializers.UUIDField(read_only=True)
    username_phone_email = serializers.CharField(required=True, write_only=True)

    class Meta:
        model = User
        fields = (
            'id',
            'auth_type',
            'auth_status',
            'username_phone_email',  # Include it in the serialized output
        )
        extra_kwargs = {
            'auth_type': {'read_only': True, 'required': False},
            'auth_status': {'read_only': True, 'required': False},
        }

    def create(self, validated_data):
        verify_value = validated_data.pop('verify_value', None)
        auth_type = validated_data.get('auth_type')

        user = User.objects.create(auth_type=auth_type)  # don't set email or phone yet

        code = user.create_verify_code(auth_type, verify_value=verify_value)

        if auth_type == VIA_EMAIL:
            send_email(verify_value, code)
        elif auth_type == VIA_PHONE:
            if False in send_phone_code(verify_value, code).values():
                raise ValidationError({
                    "message": "Xatolik yuz berdi. Iltimos qaytadan urinib ko'ring, yoki admin bilan bog'laning"
                })

        return user

    def validate(self, data):
        super(SignUpSerializer, self).validate(data)
        data = self.auth_validate(data)
        return data

    @staticmethod
    def auth_validate(data):
        user_input = str(data.get('username_phone_email')).lower()
        input_type = check_username_phone_email(user_input)
        if input_type not in ["email", "phone"]:
            raise ValidationError({
                'message': "You must send a valid email or phone number"
            })

        data['auth_type'] = VIA_EMAIL if input_type == "email" else VIA_PHONE
        data['verify_value'] = user_input  # Save it for sending code, not for saving on the model
        return data

    def validate_username_phone_email(self, value):
        # return value.lower()
        value = value.lower()
        # ic(value)
        if value and User.objects.filter(email=value, auth_status__in=[CODE_VERIFIED, DONE, PHOTO_DONE]).exists():
            data = {
                "message": "Bu email allaqachon ma'lumotlar bazasida bor"
            }
            raise ValidationError(data)
        elif value and User.objects.filter(phone_number=value, auth_status__in=[CODE_VERIFIED, DONE, PHOTO_DONE]).exists():
            data = {
                "message": "Bu telefon raqami allaqachon ma'lumotlar bazasida bor"
            }
            raise ValidationError(data)

        return value

    def to_representation(self, instance):
        data = super(SignUpSerializer, self).to_representation(instance)
        data["next_step"] = "Verify code sent to your email or phone"
        data.update(instance.token())

        return data


class ChangeUserInformation(serializers.Serializer):
    first_name = serializers.CharField(write_only=True, required=True)
    last_name = serializers.CharField(write_only=True, required=True)
    username = serializers.CharField(write_only=True, required=True)
    password = serializers.CharField(write_only=True, required=True)
    confirm_password = serializers.CharField(write_only=True, required=True)

    def validate(self, data):
        password = data.get('password', None)
        confirm_password = data.get('confirm_password', None)
        if password !=confirm_password:
            raise ValidationError(
                {
                    "message": "Parolingiz va tasdiqlash parolingiz bir-biriga teng emas"
                }
            )
        if password:
            validate_password(password)
            validate_password(confirm_password)

        return data

    def validate_username(self, username):
        if len(username) < 5 or len(username) > 30:
            raise ValidationError(
                {
                    "message": "Username must be between 5 and 30 characters long"
                }
            )
        if username.isdigit():
            raise ValidationError(
                {
                    "message": "This username is entirely numeric"
                }
            )
        return username

    def update(self, instance, validated_data):

        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)
        instance.password = validated_data.get('password', instance.password)
        instance.username = validated_data.get('username', instance.username)
        if validated_data.get('password'):
            instance.set_password(validated_data.get('password'))
        if instance.auth_status == CODE_VERIFIED:
            instance.auth_status = DONE
        instance.save()
        return instance


class ChangeUserPhotoSerializer(serializers.Serializer):
    photo = serializers.ImageField(validators=[FileExtensionValidator(allowed_extensions=[
        'jpg', 'jpeg', 'png', 'heic', 'heif'
    ])])

    def update(self, instance, validated_data):
        photo = validated_data.get('photo')
        if photo:
            instance.photo = photo
            instance.auth_status = PHOTO_DONE
            instance.save()
        return instance


class LoginSerializer(TokenObtainPairSerializer):

    def __init__(self, *args, **kwargs):
        super(LoginSerializer, self).__init__(*args, **kwargs)
        self.fields['userinput'] = serializers.CharField(required=True)
        self.fields['username'] = serializers.CharField(required=False, read_only=True)

    def auth_validate(self, data):
        user_input = data.get('userinput')  # email, phone_number, username
        if check_user_type(user_input) == 'username':
            username = user_input
        elif check_user_type(user_input) == "email":  # Anora@gmail.com   -> anOra@gmail.com
            user = self.get_user(email__iexact=user_input) # user get method orqali user o'zgartiruvchiga biriktirildi
            username = user.username
        elif check_user_type(user_input) == 'phone':
            user = self.get_user(phone_number=user_input)
            username = user.username
        else:
            data = {
                'success': True,
                'message': "Siz email, username yoki telefon raqami jonatishingiz kerak"
            }
            raise ValidationError(data)

        authentication_kwargs = {
            self.username_field: username,
            'password': data['password']
        }
        # user statusi tekshirilishi kerak
        current_user = User.objects.filter(username__iexact=username).first()  # None

        if current_user is not None and current_user.auth_status in [NEW, CODE_VERIFIED]:
            raise ValidationError(
                {
                    'message': "Siz royhatdan toliq otmagansiz!"
                }
            )
        user = authenticate(**authentication_kwargs)
        if user is not None:
            self.user = user
        else:
            raise ValidationError(
                {
                    'message': "Sorry, login or password you entered is incorrect. Please check and trg again!"
                }
            )

    def validate(self, data):
        self.auth_validate(data)
        if self.user.auth_status not in [DONE, PHOTO_DONE]:
            raise PermissionDenied("Siz login qila olmaysiz. Ruxsatingiz yoq")
        data = self.user.token()
        data['auth_status'] = self.user.auth_status
        data['full_name'] = self.user.full_name
        return data

    def get_user(self, **kwargs):
        users = User.objects.filter(**kwargs)
        # ic(users)
        
        if not users.exists():
            raise ValidationError(
                {
                    'message': "User account not found"
                }
            )
        
        if users.count() > 1:
            # Handle duplicate credentials: Decide how to handle multiple users
            # For example, raising an error or selecting the user with a more specific status
            # Here, I'm using a more specific filter to handle duplicates
            users = users.filter(auth_status=PHOTO_DONE)  # Adjust this logic based on your needs
            
            if users.count() > 1:
                # Still multiple users after filtering, raise an error or handle as needed
                raise ValidationError(
                    {
                        'message': "Duplicate user accounts found"
                    }
                )
        
        return users.first()


class LoginRefreshSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    def validate(self, attrs):
        # Get access token from the authenticated request context
        request = self.context.get('request')
        if not request or not hasattr(request, 'auth'):
            raise serializers.ValidationError("Access token missing from request.")

        access_token = request.auth  # This should be a JWT token string
        access_token_instance = AccessToken(access_token)

        user_id = access_token_instance.get('user_id')
        user = get_object_or_404(User, id=user_id)
        update_last_login(None, user)

        # Validate and rotate refresh token
        refresh_token = attrs['refresh']
        refresh = RefreshToken(refresh_token)
        data = {
            'access_token': str(refresh.access_token),
            'refresh': str(refresh),
        }

        return data


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()


class ResetPasswordSerializer(serializers.Serializer):
    username_phone_email = serializers.CharField(write_only=True, required=True)

    def validate(self, attrs):
        username_phone_email = attrs.get('username_phone_email', None)
        if username_phone_email is None:
            raise ValidationError(
                {
                    'message': "Email yoki telefon raqami kiritilishi shart!"
                }
            )
        user = User.objects.filter(Q(phone_number=username_phone_email) | Q(email=username_phone_email))
        if not user.exists():
            raise NotFound(detail="User not found")
        attrs['user'] = user.first()
        return attrs
