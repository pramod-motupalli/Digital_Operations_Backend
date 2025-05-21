from django.urls import path
from .views import (
    MyTokenObtainPairView,
    RegisterClientView,
    VerifyEmailView,
    ResendVerificationView,
    SendResetPasswordEmailView,
    VerifyForgotPasswordEmailView,
    ResetPasswordView,
    RegisterTeamLeadView,
    SendVerificationEmailView,
    ManagerCreateView,
    RegisterStaffView,
    StaffAutoRegisterView,
    RegisterAccountantView,
    team_leads_list,
)   
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path('token/', MyTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('register/', RegisterClientView.as_view(), name='register_client'),
    path('verify-email/', VerifyEmailView.as_view(), name='verify_email'),
    path('resend-verification/', ResendVerificationView.as_view(), name='resend_verification'),
    path('send-verification/', SendVerificationEmailView.as_view(), name='send_verification'),
    path('forgot-password/', SendResetPasswordEmailView.as_view(), name='forgot_password'),
    path('verify-password/<uuid:uuid>/', VerifyForgotPasswordEmailView.as_view(), name='verify_password'),
    path('reset-password/',ResetPasswordView.as_view(),name="reset_password"),
    path('register-team-lead/', RegisterTeamLeadView.as_view(), name='register_teamlead'),
    path('register-accountant/', RegisterAccountantView.as_view(), name='register-accountant'),
    path('create-manager/', ManagerCreateView.as_view(), name='create-manager'),
    path('create-staff/', RegisterStaffView.as_view(), name='create-staff'),
    path('register-staff/', StaffAutoRegisterView.as_view(), name='regester-staff'),
     path("team-leads/", team_leads_list, name="team-leads-list"),
]
