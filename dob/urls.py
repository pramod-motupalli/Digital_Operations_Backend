from django.urls import path
from .views import (
    MyTokenObtainPairView,
    RegisterClientView,
    VerifyEmailView,
    ResendVerificationView,
)
from .views import SendVerificationEmailView 
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path('login/', MyTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('register/', RegisterClientView.as_view(), name='register_client'),
    path('verify-email/<uidb64>/<token>/', VerifyEmailView.as_view(), name='verify_email'),
    path('resend-verification/', ResendVerificationView.as_view(), name='resend_verification'),
    path('send-verification/', SendVerificationEmailView.as_view(), name='send_verification'),
]
