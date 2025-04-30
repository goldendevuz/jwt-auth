from django.urls import path

from apps.v1.shared.views import PasswordGeneratorView
from .views import CreateUserView, VerifyAPIView, GetNewVerification, \
    ChangeUserInformationView, ChangeUserPhotoView, LoginView, LoginRefreshView, \
    LogOutView, ForgotPasswordView, ResetPasswordView

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path('login/refresh/', LoginRefreshView.as_view()),
    path('logout/', LogOutView.as_view()),
    path('signup/', CreateUserView.as_view(), name='signup'),
    path('verify/', VerifyAPIView.as_view(), name='verify'),
    path('new-verify/', GetNewVerification.as_view()),
    path('', ChangeUserInformationView.as_view()),
    path('photo/', ChangeUserPhotoView.as_view()),
    path('reset-password/', ForgotPasswordView.as_view()),
    path('generate-password/', PasswordGeneratorView.as_view(), name='generate-password'),
]