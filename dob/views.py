from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status,generics
from rest_framework.permissions import AllowAny,IsAuthenticated
from rest_framework_simplejwt.views import TokenObtainPairView,TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.mail import send_mail
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.conf import settings
from django.shortcuts import redirect, get_object_or_404
from django.http import JsonResponse
from dob.models import CustomUser
from .serializers import ClientRegistrationSerializer, TokenRefreshSerializer ,MyTokenObtainPairSerializer, ResetPasswordSerializer,TeamLeadRegistrationSerializer,ManagerProfileSerializer,StaffRegistrationSerializer,AccountantRegistrationSerializer
from .emails import send_email_verification_link
# from rest_framework_simplejwt.serializers import TokenRefreshSerializer
import uuid

User = get_user_model()

class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer
    def validate(self, attrs):
        data = super().validate(attrs)
        # print(data)
        # `self.user` is the authenticated user instance
        data['role'] = self.user.role
        data['is_email_verified'] = self.user.is_email_verified
        # print(self.user.is_email_verified)
        return data


class TokenRefreshView(TokenRefreshView):
    serializer_class = TokenRefreshSerializer

    def post(self, request, *args, **kwargs):
        # Optional: Add logging or custom pre-processing here
        print("Token refresh requested")
        response = super().post(request, *args, **kwargs)
        # Optional: Modify response data here if needed
        return response

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
        access_token = str(refresh.access_token)
        refresh_token = str(refresh)

        return Response({
            "message": "Client registered successfully. Please verify your email.",
            "access_token": access_token,
            "refresh_token": refresh_token,
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


# class IsSuperUser(permissions.BasePermission):
#     def has_permission(self, request, view):
#         return request.user and request.user.is_superuser

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

        # Required fields
        name = data.get('name')
        email = data.get('email')
        designation = data.get('designation')
        team_lead_username = data.get('team_lead') or data.get('teamLead')


        if not all([name, email, designation, team_lead_username]):
            return Response({'error': 'Missing required fields.'}, status=status.HTTP_400_BAD_REQUEST)

        # Split name into first and last
        name_parts = name.strip().split()
        first_name = name_parts[0]
        last_name = " ".join(name_parts[1:]) if len(name_parts) > 1 else ""

        # Generate unique username
        base_username = name.replace(" ", "").lower()
        existing_count = CustomUser.objects.filter(username__startswith=base_username).count()
        username = f"{base_username}{existing_count + 1 if existing_count else ''}"

        # Set password
        password = f"staff{existing_count + 1 if existing_count else 1}"

        # Populate data for serializer
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

            # ✅ Send email to the staff member
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
        uuid = request.data.get("uuid")
        if not uuid:
            return Response({"error": "UUID is required."}, status=400)

        try:
            user = CustomUser.objects.get(email_verification_uuid=uuid)
        except CustomUser.DoesNotExist:
            return Response({"error": "Invalid or expired verification link."}, status=400)

        if user.is_email_verified:
            return Response({"message": "Email already verified."}, status=200)

        # Mark user as verified and active
        user.is_email_verified = True
        user.is_active = True
        user.email_verification_uuid = None
        user.save()

        return Response({"message": "Email verified successfully."}, status=200)

        # return redirect(f"{settings.FRONTEND_URL}/client")

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

        # Ensure email_verification_uuid exists
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
            return Response({"error": f"Failed to send email: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({"message": "Verification email sent."}, status=status.HTTP_200_OK)

class SendResetPasswordEmailView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        # 1. Validate incoming email
        email = request.data.get('email')
        if not email:
            return Response({"error": "Email is required"}, status=status.HTTP_400_BAD_REQUEST)

        # 2. Lookup user
        user = get_object_or_404(CustomUser, email=email)

        # 3. Generate & save a new UUID
        user.email_verification_uuid = uuid.uuid4()
        user.save()

        # 4. Build the full verification URL
        reset_path = reverse("verify_password", kwargs={"uuid": str(user.email_verification_uuid)})
        verification_url = request.build_absolute_uri(reset_path)

        # 5. Send the verification email
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
            return Response(
                {"error": f"Failed to send email: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        return Response(
            {"message": "Verification email sent."},
            status=status.HTTP_200_OK
        )


class VerifyForgotPasswordEmailView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, uuid):
        try:
            user = CustomUser.objects.get(email_verification_uuid=uuid)
        except CustomUser.DoesNotExist:
            return redirect(f"{settings.FRONTEND_URL}/invalid-link")  # optional: handle invalid case in frontend

        user.is_email_verified = True
        user.is_active = True
        user.email_verification_uuid = None
        user.save()

        return redirect(f"{settings.FRONTEND_URL}/reset-password")


class ResetPasswordView(APIView):
    permission_classes = [IsAuthenticated]  # Require valid token

    def post(self, request):
        serializer = ResetPasswordSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"detail": "Password has been reset successfully."},
                status=status.HTTP_200_OK
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


def team_leads_list(request):
    if request.method == 'GET':
        leads = CustomUser.objects.filter(role='team_lead').values_list('username', flat=True)
        return JsonResponse(list(leads), safe=False)

