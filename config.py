import os

from environs import Env
from icecream import ic

env = Env()

# Construct the full absolute path to the .env file (parent of config)
env_file_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '.env'))

# Check if it exists before reading
if not os.path.exists(env_file_path):
    ic(f"File not found: {env_file_path}")
    ic('.env fayli topilmadi!')
    ic('.env.example faylidan nusxa ko\'chirib shablonni o\'zizga moslang.')
    exit(1)

# Load the .env file
env.read_env(env_file_path)

# Use environment variables
SECRET_KEY = env.str('SECRET_KEY', default='djangorestframework')
DEBUG = env.bool('DEBUG', default=True)
ADMIN_URL = env.str('ADMIN_URL', default='admin/')
ALLOWED_HOSTS = env.list("ALLOWED_HOSTS", default=['*'])
CSRF_TRUSTED_ORIGINS = env.list("CSRF_TRUSTED_ORIGINS", default=['http://127.0.0.1'])
CORS_ALLOWED_ORIGINS = env.list("CORS_ALLOWED_ORIGINS", default=['http://127.0.0.1'])
EMAIL_HOST_USER = env.str('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = env.str('EMAIL_HOST_PASSWORD')
API_V1_URL = env.str('API_V1_URL', default='')
ACCESS_TOKEN_LIFETIME=env.int('ACCESS_TOKEN_LIFETIME', default=5)
REFRESH_TOKEN_LIFETIME=env.int('REFRESH_TOKEN_LIFETIME', default=1)