from django.urls import path
from .views import *

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
    path('domain-hosting/', DomainHostingView.as_view(), name='domain-hosting-list'),
    path('domain-hosting/<int:pk>/', DomainHostingView.as_view(), name='domain-hosting-detail'),



    path('workspaces/', WorkspaceListCreateView.as_view(), name='workspace-list-create'),
    path('workspaces/<int:pk>/',WorkspaceDetailView.as_view(), name='workspace-detail'),

    # Task URLs for a specific workspace
    path('workspaces/<int:workspace_id>/tasks/', WorkspaceTaskListCreateView.as_view(), name='workspace-tasks-list-create'),
    path('assign-spoc/', AssignSpocView.as_view(), name='assign-spoc'),
    path('team-leads/no-spoc/', team_leads_list_no_spoc, name='team-leads-no-spoc'),
    path('staff-members/', staff_members_list, name='staff-members-list'),
    path('details/',get_logged_in_client.as_view(), name='get_logged_in_client'),
    path('workspaces/client/', client_workspaces_view, name='client-workspaces'),
    path('workspaces/spoc/', spoc_workspaces_view, name='spoc-workspaces'),
    path('workspaces/hd/', hd_maintenance_workspaces_view, name='hd-workspaces'),
    path('workspaces/staff/', staff_workspaces_view, name='staff-workspaces'),

    path('spoc/tasks/', SPOCTaskListView.as_view(), name='spoc-task-list'),
    # path('tasks/<int:task_id>/assign-staff/', AssignStaffToTaskView.as_view(), name='assign-staff-task'),
    path('spoc/tasks/<int:task_id>/update-status/', AssignStatusView.as_view(), name='assign-status-task'),
    path('tasks/out-of-scope/', OutOfScopeTasksView.as_view(), name='out_of_scope_tasks'),
    path('tasks/raise-request/<int:pk>/', RaiseTaskRequestView.as_view()),
    path('tasks/<int:pk>/accept/', AcceptTaskView.as_view(), name='accept-task'),
    path('tasks/<int:pk>/reject/', RejectTaskView.as_view()),
    path('tasks/<int:pk>/payment-done/', MarkPaymentDoneView.as_view()),
    path('tasks/<int:pk>/raise-to-spoc/', RaiseToSPOCView.as_view(), name='raise-to-spoc'),
    path('tasks/raised-to-spoc/', RaisedToSPOCTasksView.as_view(), name='raised-to-spoc-tasks'),
<<<<<<< HEAD
    path('tasks/<int:task_id>/assign-staff/', AssignMultipleStaffToTaskView.as_view(), name='assign-staff-to-task'),

    path('staff/tasks/cards/', get_spoc_tasks, name='staff-task-cards'),
    path('staff/tasks/cards/<int:pk>/', TaskStatusUpdateView.as_view(), name='task-status-update'),
    path('notifications/my/', get_my_notifications, name='my-notifications'),

=======
    path('clients/tasks/', ClientOutOfScopeTasksView.as_view(), name='client-workspace-tasks'),
>>>>>>> f39251a42b84beeb29b2d68261a30ccd618b511b
]
