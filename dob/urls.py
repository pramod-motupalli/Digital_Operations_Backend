from django.urls import path
from .views import (
    MyTokenObtainPairView,
    RegisterClientView,
    VerifyEmailView,
    ResendVerificationView,
    SendResetPasswordEmailView,
    VerifyForgotPasswordEmailView,
    ResetPasswordView
)
from .views import SendVerificationEmailView 
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path('token/', MyTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('register/', RegisterClientView.as_view(), name='register_client'),
    path('verify-email/<uuid:uuid>/', VerifyEmailView.as_view(), name='verify_email'),
    path('resend-verification/', ResendVerificationView.as_view(), name='resend_verification'),
    path('send-verification/', SendVerificationEmailView.as_view(), name='send_verification'),
    path('forgot-password/', SendResetPasswordEmailView.as_view(), name='forgot_password'),
    path('verify-password/<uuid:uuid>/', VerifyForgotPasswordEmailView.as_view(), name='verify_password'),
    path('reset-password/<uuid:uuid>/',ResetPasswordView.as_view(),name="reset_password"),
]
