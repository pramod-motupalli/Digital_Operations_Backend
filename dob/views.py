from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework.response import Response
from rest_framework import status, generics, viewsets, permissions
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.decorators import api_view, permission_classes
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.mail import send_mail
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.conf import settings
from django.shortcuts import redirect, get_object_or_404
from django.http import JsonResponse
from dob.models import CustomUser, Plan, DomainHosting, PlanRequest, PaymentRequest, Workspace
from .serializers import (
    ClientRegistrationSerializer,
    TokenRefreshSerializer,
    MyTokenObtainPairSerializer,
    ResetPasswordSerializer,
    TeamLeadRegistrationSerializer,
    ManagerProfileSerializer,
    StaffRegistrationSerializer,
    AccountantRegistrationSerializer,
    TeamLeadAutoRegistrationSerializer,
    PlanSerializer,
    DomainHostingSerializer,
    PlanRequestSerializer,
    PaymentRequestSerializer,
    WorkspaceSerializer,
)
from .emails import send_email_verification_link
import uuid

User = get_user_model()


def refresh_access_token(refresh_token):
    try:
        refresh = RefreshToken(refresh_token)
        new_access_token = str(refresh.access_token)
        return new_access_token
    except TokenError as e:
        return None

class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer

    def validate(self, attrs):
        data = super().validate(attrs)
        data['role'] = self.user.role
        data['is_email_verified'] = self.user.is_email_verified
        return data


class TokenRefreshView(TokenRefreshView):
    serializer_class = TokenRefreshSerializer

    def post(self, request, *args, **kwargs):
        print("Token refresh requested")
        return super().post(request, *args, **kwargs)


class UserMeView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        return Response({
            "id": user.id,
            "email": user.email,
            "role": user.role,
            "name": user.get_full_name(),
        })


class RegisterClientView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = ClientRegistrationSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user = serializer.save(is_active=False)
        send_email_verification_link(user, signup=True, role='client')

        refresh = RefreshToken.for_user(user)
        return Response({
            "message": "Client registered successfully. Please verify your email.",
            "access_token": str(refresh.access_token),
            "refresh_token": str(refresh),
        }, status=status.HTTP_201_CREATED)


class RegisterTeamLeadView(APIView):
    permission_classes = []

    def post(self, request):
        serializer = TeamLeadRegistrationSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        teamlead_profile = serializer.save()
        return Response({
            "message": "Team lead created successfully.",
            "username": teamlead_profile.user.username,
            "email": teamlead_profile.user.email
        }, status=status.HTTP_201_CREATED)


class TeamLeadAutoRegisterView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        print("Request user:", request.user)
        print("Is authenticated:", request.user.is_authenticated)

        serializer = TeamLeadAutoRegistrationSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            team_lead = serializer.save()
            return Response({
                "message": "Team Lead registered successfully",
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class ManagerCreateView(generics.CreateAPIView):
    queryset = CustomUser.objects.filter(role=CustomUser.ROLE_MANAGER)
    serializer_class = ManagerProfileSerializer
    permission_classes = []


class RegisterStaffView(APIView):
    permission_classes = []

    def post(self, request):
        serializer = StaffRegistrationSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        staff_profile = serializer.save()
        return Response({
            "message": "Staff registered successfully.",
            "username": staff_profile.user.username,
            "email": staff_profile.user.email,
            "team_lead": staff_profile.team_lead.user.username
        }, status=status.HTTP_201_CREATED)


class StaffAutoRegisterView(APIView):
    permission_classes = []

    def post(self, request):
        data = request.data.copy()

        name = data.get('name')
        email = data.get('email')
        designation = data.get('designation')
        team_lead_username = data.get('team_lead') or data.get('teamLead')

        if not all([name, email, designation, team_lead_username]):
            return Response({'error': 'Missing required fields.'}, status=status.HTTP_400_BAD_REQUEST)

        name_parts = name.strip().split()
        first_name = name_parts[0]
        last_name = " ".join(name_parts[1:]) if len(name_parts) > 1 else ""
        base_username = name.replace(" ", "").lower()
        existing_count = CustomUser.objects.filter(username__startswith=base_username).count()
        username = f"{base_username}{existing_count + 1 if existing_count else ''}"
        password = f"staff{existing_count + 1 if existing_count else 1}"

        data = {
            'email': email,
            'username': username,
            'first_name': first_name,
            'last_name': last_name,
            'password': password,
            'designation': designation,
            'team_lead_username': team_lead_username
        }

        serializer = StaffRegistrationSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            try:
                send_mail(
                    subject='Your Staff Account Credentials',
                    message=f"Hello {first_name},\n\nYour account has been created.\n\nUsername: {username}\nPassword: {password}\n\nPlease log in and change your password.",
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[email],
                    fail_silently=False,
                )
            except Exception as e:
                return Response({
                    'message': 'Staff registered but email could not be sent.',
                    'username': username,
                    'password': password,
                    'error': str(e)
                }, status=status.HTTP_201_CREATED)

            return Response({
                'message': 'Staff registered and email sent successfully.',
                'username': username,
                'password': password
            }, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class RegisterAccountantView(APIView):
    permission_classes = []

    def post(self, request):
        serializer = AccountantRegistrationSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        accountant_profile = serializer.save()
        return Response({
            "message": "Accountant registered successfully.",
            "username": accountant_profile.user.username,
            "email": accountant_profile.user.email,
            "manager": accountant_profile.parent.user.username
        }, status=status.HTTP_201_CREATED)


class VerifyEmailView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        uuid_str = request.data.get("uuid")
        if not uuid_str:
            return Response({"error": "UUID is required."}, status=400)

        try:
            user = CustomUser.objects.get(email_verification_uuid=uuid_str)
        except CustomUser.DoesNotExist:
            return Response({"error": "Invalid or expired verification link."}, status=400)

        if user.is_email_verified:
            return Response({"message": "Email already verified."}, status=200)

        user.is_email_verified = True
        user.is_active = True
        user.email_verification_uuid = None
        user.save()

        return Response({"message": "Email verified successfully."}, status=200)


class ResendVerificationView(APIView):
    def post(self, request):
        email = request.data.get('email')
        try:
            user = User.objects.get(email=email)
            if not user.is_active:
                send_email_verification_link(user, signup=True, role='client')
                return Response({"message": "Verification email resent."}, status=status.HTTP_200_OK)
            return Response({"message": "Email already verified."}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)


class SendVerificationEmailView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({"error": "Email is required"}, status=status.HTTP_400_BAD_REQUEST)

        user = get_object_or_404(CustomUser, email=email)

        if not user.email_verification_uuid:
            user.email_verification_uuid = uuid.uuid4()
            user.save()
        if user.is_email_verified:
            return Response({"message": "Email already verified."}, status=status.HTTP_200_OK)

        verification_link = f"{settings.FRONTEND_URL}/identity?uuid={user.email_verification_uuid}"

        try:
            send_mail(
                subject="Please verify your email",
                message=(
                    f"Hello {user.first_name},\n\n"
                    f"Click the link below to verify your email address:\n\n"
                    f"{verification_link}\n\n"
                    "If you did not request this, please ignore this email."
                ),
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                fail_silently=False,
            )
        except Exception as e:
            return Response({"error": f"Failed to send email: {str(e)}"}, status=500)

        return Response({"message": "Verification email sent."}, status=200)


class SendResetPasswordEmailView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({"error": "Email is required"}, status=400)

        user = get_object_or_404(CustomUser, email=email)
        user.email_verification_uuid = uuid.uuid4()
        user.save()

        reset_path = reverse("verify_password", kwargs={"uuid": str(user.email_verification_uuid)})
        verification_url = request.build_absolute_uri(reset_path)

        try:
            send_mail(
                subject="Password Reset Verification",
                message=(
                    f"Hello {user.first_name},\n\n"
                    f"Click the link below to reset your password:\n\n"
                    f"{verification_url}\n\n"
                    "If you didn’t request this, you can ignore this email."
                ),
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                fail_silently=False,
            )
        except Exception as e:
            return Response({"error": f"Failed to send email: {str(e)}"}, status=500)

        return Response({"message": "Verification email sent."}, status=200)


class VerifyForgotPasswordEmailView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, uuid):
        try:
            user = CustomUser.objects.get(email_verification_uuid=uuid)
        except CustomUser.DoesNotExist:
            return redirect(f"{settings.FRONTEND_URL}/invalid-link")

        user.is_email_verified = True
        user.is_active = True
        user.email_verification_uuid = None
        user.save()

        return redirect(f"{settings.FRONTEND_URL}/reset-password")


class ResetPasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ResetPasswordSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response({"detail": "Password has been reset successfully."}, status=200)
        return Response(serializer.errors, status=400)


@api_view(['GET'])
def team_leads_list(request):
    leads = CustomUser.objects.filter(role='team_lead').values_list('username', flat=True)
    return JsonResponse(list(leads), safe=False)


class SubmissionView(APIView):
    permission_classes = []

    def post(self, request):
        try:
            title = request.data.get('title')
            billing = request.data.get('billing')
            features = request.data.get('features')
            price = request.data.get('price')
            domain_hosting = request.data.get('domain_hosting')
            domain = None  # Default if domain is not created

            # Always create Plan
            plan = Plan.objects.create(
                title=title,
                price=price,
                billing=billing,
                features=features
            )

            # Create PlanRequest if plan is a customization
            if title and title.lower() == "plan customization":
                PlanRequest.objects.create(plan=plan)

            # Check if any domain hosting field is filled
            if domain_hosting and isinstance(domain_hosting, dict):
                important_fields = [
                    domain_hosting.get('domainName'),
                    domain_hosting.get('domainProvider'),
                    domain_hosting.get('domainAccount'),
                    domain_hosting.get('domainExpiry'),
                    domain_hosting.get('hostingProvider'),
                    domain_hosting.get('hostingProviderName'),
                    domain_hosting.get('hostingExpiry'),
                    domain_hosting.get('clientName'),
                    domain_hosting.get('phoneNumber'),
                    domain_hosting.get('email'),
                    domain_hosting.get('assignedTo'),
                ]

                # Create DomainHosting only if any field is non-empty
                if any(f for f in important_fields if f and str(f).strip()):
                    domain = DomainHosting.objects.create(
                        plan=plan,
                        domain_name=domain_hosting.get('domainName', ''),
                        domain_provider=domain_hosting.get('domainProvider', ''),
                        domain_account=domain_hosting.get('domainAccount', ''),
                        domain_expiry=domain_hosting.get('domainExpiry'),
                        hosting_provider=domain_hosting.get('hostingProvider', ''),
                        hosting_provider_name=domain_hosting.get('hostingProviderName', ''),
                        hosting_expiry=domain_hosting.get('hostingExpiry'),
                        client_name=domain_hosting.get('clientName'),
                        phone_number=domain_hosting.get('phoneNumber'),
                        email=domain_hosting.get('email'),
                        assigned_to=domain_hosting.get('assignedTo'),
                    )

            return Response({
                'message': 'Submission successful',
                'plan_id': plan.id,
                'domain_id': domain.id if domain else None
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            import traceback
            traceback.print_exc()
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    def get(self, request):
        domain_hostings = Plan.objects.all()
        serializer = PlanSerializer(domain_hostings, many=True)
        return Response(serializer.data)
class DomainHostingView(APIView):
    permission_classes = [AllowAny]
    def get(self, request):
        domain_hostings = DomainHosting.objects.all()
        serializer = DomainHostingSerializer(domain_hostings, many=True)
        return Response(serializer.data)
    
@api_view(['POST'])
@permission_classes([AllowAny])
def approve_payment(request, plan_id):
    try:
        plan = Plan.objects.get(id=plan_id)
        plan.payment_is_approved = True
        plan.save()
        return Response({'message': 'Payment approved successfully'}, status=status.HTTP_200_OK)
    except Plan.DoesNotExist:
        return Response({'error': 'Plan not found'}, status=status.HTTP_404_NOT_FOUND)

@api_view(['PATCH'])
@permission_classes([AllowAny])
def activate_workspace(request, pk):
    try:
        plan = Plan.objects.get(pk=pk)
        plan.is_workspace_activated = True
        plan.save()
        return Response({'message': 'Workspace activated successfully'}, status=status.HTTP_200_OK)
    except Plan.DoesNotExist:
        return Response({'error': 'Plan not found'}, status=status.HTTP_404_NOT_FOUND)


@api_view(['GET', 'PATCH'])
@permission_classes([AllowAny]) #change permissions
def get_or_update_requests(request):
    if request.method == 'GET':
        requests = PlanRequest.objects.all()
        serializer = PlanRequestSerializer(requests, many=True)
        return Response(serializer.data)

    if request.method == 'PATCH':
        req_id = request.data.get('id')
        new_price = request.data.get('price')

        if not req_id or new_price is None:
            return Response({'error': 'Invalid data'}, status=400)

        try:
            req = PlanRequest.objects.get(id=req_id)
            req.overridden_price = new_price
            req.is_approved = True   # <--- add this line here
            req.save()
            return Response({'message': 'Price updated and request approved'})
        except PlanRequest.DoesNotExist:
            return Response({'error': 'Request not found'}, status=404)



# class PaymentRequestViewSet(viewsets.ModelViewSet):
#     permission_classes=[AllowAny]
#     queryset = PaymentRequest.objects.all()
#     serializer_class = PaymentRequestSerializer
class PaymentRequestView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        try:
            payment_requests = PaymentRequest.objects.all()
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        serializer = PaymentRequestSerializer(payment_requests, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        plan_request_id = request.data.get('plan_request')
        price = request.data.get('price')

        try:
            plan_request = PlanRequest.objects.get(id=plan_request_id)

            # Save price to the Plan model
            if plan_request.plan:
                plan_request.plan.price = price
                plan_request.plan.save()

            # ✅ Save price to PaymentRequest model as well
            payment_request = PaymentRequest.objects.create(
                plan_request=plan_request,
                price=price  # ✅ explicitly save it
            )

            serializer = PaymentRequestSerializer(payment_request)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        except PlanRequest.DoesNotExist:
            return Response({'error': 'PlanRequest not found'}, status=status.HTTP_404_NOT_FOUND)


class WorkspaceCreateAPIView(APIView):
    permission_classes = [AllowAny]

    # CREATE new workspace
    def post(self, request):
        serializer = WorkspaceSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Workspace created successfully!'}, status=status.HTTP_201_CREATED)
        print(serializer.errors)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # LIST all workspaces
    def get(self, request):
        workspaces = Workspace.objects.all()
        serializer = WorkspaceSerializer(workspaces, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    # FULL UPDATE existing workspace
    def put(self, request, pk=None):
        if not pk:
            return Response({'error': 'Workspace ID is required for update.'}, status=status.HTTP_400_BAD_REQUEST)
        workspace = get_object_or_404(Workspace, pk=pk)
        serializer = WorkspaceSerializer(workspace, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Workspace updated successfully!'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # PARTIAL UPDATE existing workspace
    def patch(self, request, pk=None):
        if not pk:
            return Response({'error': 'Workspace ID is required for partial update.'}, status=status.HTTP_400_BAD_REQUEST)
        workspace = get_object_or_404(Workspace, pk=pk)
        serializer = WorkspaceSerializer(workspace, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Workspace partially updated!'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)