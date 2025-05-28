from django.urls import path
from .views import (
    MyTokenObtainPairView,
    UserMeView,
    TokenRefreshView,
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
    SubmissionView,
    get_or_update_requests,
    PaymentRequestViewSet,
    TeamLeadAutoRegisterView,
    AccountantAutoRegisterView,
    MarkIsVisitedView,TeamLeadListView, StaffListView, AccountantListView,
    PaymentRequestView,approve_payment,activate_workspace,WorkspaceCreateAPIView, DomainHostingView,WorkspaceListCreateView,WorkspaceTaskListCreateView,
    WorkspaceDetailView, AssignSpocView,team_leads_list_no_spoc,
)

urlpatterns = [
    path('token/', MyTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('me/', UserMeView.as_view(), name='user-me'),
    
    # Registration & Verification
    path('register/', RegisterClientView.as_view(), name='register_client'),
    path('verify-email/', VerifyEmailView.as_view(), name='verify_email'),
    path('resend-verification/', ResendVerificationView.as_view(), name='resend_verification'),
    path('send-verification/', SendVerificationEmailView.as_view(), name='send_verification'),

    # Password Reset
    path('forgot-password/', SendResetPasswordEmailView.as_view(), name='forgot_password'),
    path('verify-password/<uuid:uuid>/', VerifyForgotPasswordEmailView.as_view(), name='verify_password'),
    path('reset-password/', ResetPasswordView.as_view(), name='reset_password'),

    # Staff Registration
    path('register-team-lead/', RegisterTeamLeadView.as_view(), name='register_teamlead'),
    path('register-accountant/', RegisterAccountantView.as_view(), name='register-accountant'),
    path('create-manager/', ManagerCreateView.as_view(), name='create-manager'),
    path('create-staff/', RegisterStaffView.as_view(), name='create-staff'),
    path('register-staff/', StaffAutoRegisterView.as_view(), name='register-staff'),
    path('teamlead/register/', TeamLeadAutoRegisterView.as_view(), name='teamlead-register'),
    path("create-accountant/", AccountantAutoRegisterView.as_view(), name="create-accountant"),

    # Misc Views
    path('team-leads/', team_leads_list, name='team-leads-list'),
    path('get-team-leads/', TeamLeadListView.as_view(), name='team-leads'),
    path('get-staff-members/', StaffListView.as_view(), name='staff-members'),
    path('get-accountants/', AccountantListView.as_view(), name='accountants'),
    path('mark-visited/', MarkIsVisitedView.as_view(), name='mark-visited'),
    path('submissions/', SubmissionView.as_view(), name='submissions'),
    path('plan-requests/', get_or_update_requests, name='plan-requests'),
    path('payment-requests/', PaymentRequestView.as_view(), name='payment-requests'),
    path('<int:plan_id>/approve/', approve_payment, name='approve-payment'),
    path('<int:pk>/activate/', activate_workspace, name='activate-workspace'),
    path('workspaces/create/', WorkspaceCreateAPIView.as_view(), name='create-workspace'),
    path('workspaces/create/<int:pk>/', WorkspaceCreateAPIView.as_view(), name='workspace-update'),
    path('domain-hosting/', DomainHostingView.as_view(), name='domain-hosting'),



     path('workspaces/', WorkspaceListCreateView.as_view(), name='workspace-list-create'),
    path('workspaces/<int:pk>/',WorkspaceDetailView.as_view(), name='workspace-detail'),

    # Task URLs for a specific workspace
    path('workspaces/<int:workspace_id>/tasks/', WorkspaceTaskListCreateView.as_view(), name='workspace-tasks-list-create'),
    path('assign-spoc/', AssignSpocView.as_view(), name='assign-spoc'),
     path('team-leads/no-spoc/', team_leads_list_no_spoc, name='team-leads-no-spoc'),

]
