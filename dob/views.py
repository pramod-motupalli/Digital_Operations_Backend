from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.mail import send_mail
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.conf import settings
from django.shortcuts import redirect, get_object_or_404
from dob.models import CustomUser
from .serializers import ClientRegistrationSerializer, MyTokenObtainPairSerializer, ResetPasswordSerializer
from .emails import send_email_verification_link
import uuid

User = get_user_model()

class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer
    def validate(self, attrs):
        data = super().validate(attrs)
        # `self.user` is the authenticated user instance
        data['role'] = self.user.role
        return data

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

class VerifyEmailView(APIView):
    permission_classes = []

    def get(self, request, uuid):
        user = get_object_or_404(CustomUser, email_verification_uuid=uuid)
        user.is_email_verified = True
        user.is_active = True
        user.email_verification_uuid = None
        user.save()
        return redirect(f"{settings.FRONTEND_URL}/client")

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
        uuid_str = str(user.email_verification_uuid)
        path = reverse('verify_email', kwargs={'uuid': uuid_str})
        verification_url = request.build_absolute_uri(path)

        send_mail(
            subject="Please verify your email",
            message=(
                f"Hello {user.first_name},\n\n"
                f"Click the link below to verify your email address:\n\n"
                f"{verification_url}\n\n"
                "If you did not request this, please ignore this email."
            ),
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=False,
        )

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

        # 3. Generate & save a new UUID if none exists
        if not user.email_verification_uuid:
            user.email_verification_uuid = uuid.uuid4()
            user.save()

        # 4. Reverse the URL with matching name & kwarg
        path = reverse(
            "verify_password",
            kwargs={"uuid": str(user.email_verification_uuid)}
        )
        verification_url = request.build_absolute_uri(path)

        # 5. Send the verification email
        send_mail(
            subject="Password Reset Verification",
            message=(
                f"Hello {user.first_name},\n\n"
                f"Click here to reset your password:\n{verification_url}\n\n"
                "If you didn’t request this, ignore this email."
            ),
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=False,
        )

        return Response(
            {"message": "Verification email sent."},
            status=status.HTTP_200_OK
        )

class VerifyForgotPasswordEmailView(APIView):
    permission_classes = []

    def get(self, request, uuid):
        user = get_object_or_404(CustomUser, email_verification_uuid=uuid)
        user.is_email_verified = True
        user.is_active = True
        user.email_verification_uuid = None
        user.save()
        return redirect(f"{settings.FRONTEND_URL}/reset-password")
    


class ResetPasswordView(APIView):
    permission_classes = []  # AllowAny if you want public

    def post(self, request):
        serializer = ResetPasswordSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        serializer.save()
        return Response(
            {"detail": "Password has been reset successfully."},
            status=status.HTTP_200_OK
        )
