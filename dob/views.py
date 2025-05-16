from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator
from rest_framework.permissions import AllowAny
from .serializers import ClientRegistrationSerializer, MyTokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from .emails import send_email_verification_link  # Your email sending function
from django.core.mail import send_mail
from django.contrib.auth import get_user_model
from django.utils.crypto import get_random_string
from django.urls import reverse


# Custom login view using email (JWT)
class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer


# Registration view with email verification trigger
class RegisterClientView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = ClientRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save(is_active=False)  # deactivate user until email verified
            send_email_verification_link(user, signup=True, role='client')
            return Response({"message": "Client registered successfully. Please verify your email."}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Email verification view
class VerifyEmailView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, uidb64=None, token=None):
        # Your verification logic here using uidb64 and token

        # Example: decode uidb64 to get user id, then verify token...

        # (Replace the following with your actual verification logic)
        try:
            # decode uidb64 to user id
            from django.utils.http import urlsafe_base64_decode
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({"error": "Invalid user"}, status=400)

        # Verify token (your token verification logic)
        if user.email_verification_token != token:
            return Response({"error": "Invalid or expired token"}, status=400)

        # Mark user as verified
        user.is_email_verified = True
        user.email_verification_token = ""
        user.save()

        # Redirect or respond with success
        frontend_login_url = self.settings.FRONTEND_URL + "/login"
        return redirect(frontend_login_url)


# Optional: Resend verification email if needed
class ResendVerificationView(APIView):
    def post(self, request):
        email = request.data.get('email')
        try:
            user = User.objects.get(email=email)
            if not user.is_active:
                send_email_verification_link(user, signup=True, role='client')
                return Response({"message": "Verification email resent."}, status=status.HTTP_200_OK)
            else:
                return Response({"message": "Email already verified."}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.core.mail import send_mail
from django.contrib.auth import get_user_model
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes

User = get_user_model()

class SendVerificationEmailView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({"error": "Email is required"}, status=400)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"error": "User with this email does not exist"}, status=404)

        token = get_random_string(32)
        user.email_verification_token = token  # Make sure this field exists in your model
        user.save()

        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
        verification_url = request.build_absolute_uri(
            reverse('verify_email', kwargs={'uidb64': uidb64, 'token': token})
        )

        subject = 'Verify your email address'
        message = f'Hi {user.username},\n\nPlease click the link to verify:\n{verification_url}\n\nThanks!'
        from_email = 'no-reply@yourdomain.com'
        recipient_list = [email]

        send_mail(subject, message, from_email, recipient_list)

        return Response({"message": "Verification email sent."})
