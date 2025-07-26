import os
from decouple import config, Csv
from icecream import ic

# Construct the full absolute path to the .env file
env_file_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '.env'))

# Check if it exists before proceeding
if not os.path.exists(env_file_path):
    ic(f"File not found: {env_file_path}")
    ic('.env fayli topilmadi!')
    ic('.env.example faylidan nusxa ko\'chirib shablonni o\'zizga moslang.')
    exit(1)

# Environment variable parsing
SECRET_KEY = config('SECRET_KEY', default='djangorestframework')
DEBUG = config('DEBUG', cast=bool, default=True)
ADMIN_URL = config('ADMIN_URL', default='admin/')

ALLOWED_HOSTS = config('ALLOWED_HOSTS', cast=Csv(), default='*')
CSRF_TRUSTED_ORIGINS = config('CSRF_TRUSTED_ORIGINS', cast=Csv(), default='http://127.0.0.1')
CORS_ALLOWED_ORIGINS = config('CORS_ALLOWED_ORIGINS', cast=Csv(), default='http://127.0.0.1')

EMAIL_HOST_USER = config('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD')

API_V1_URL = config('API_V1_URL', default='')

ACCESS_TOKEN_LIFETIME = config('ACCESS_TOKEN_LIFETIME', cast=int, default=5)
REFRESH_TOKEN_LIFETIME = config('REFRESH_TOKEN_LIFETIME', cast=int, default=1)
