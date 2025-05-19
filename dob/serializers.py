from rest_framework import serializers
from django.contrib.auth import authenticate
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from .models import CustomUser, ClientProfile
from rest_framework import serializers
from django.contrib.auth import get_user_model

# Registration serializer
from rest_framework import serializers
from .models import CustomUser, ClientProfile

class ClientRegistrationSerializer(serializers.ModelSerializer):
    phone_number = serializers.CharField(write_only=True)  # ✅ manually declare this extra field

    class Meta:
        model = CustomUser
        fields = ['email', 'username', 'first_name', 'last_name', 'password', 'phone_number']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        # Pop phone_number from validated_data so it doesn't go to CustomUser
        phone_number = validated_data.pop('phone_number')

        user = CustomUser.objects.create_user(
            email=validated_data['email'],
            username=validated_data['username'],
            first_name=validated_data['first_name'],
            last_name=validated_data.get('last_name', ''),
            password=validated_data['password'],
        )

        # Now use phone_number while creating ClientProfile
        ClientProfile.objects.create(
            user=user,
            company_name="N/A",
            contact_number=phone_number  # Make sure ClientProfile model has 'contact_number' field
        )

        return user


# Custom JWT serializer using email
class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    username_field = 'email'  # This will tell SimpleJWT to use 'email' instead of 'username'

    def validate(self, attrs):
        email = attrs.get("email")
        password = attrs.get("password")

        if not email or not password:
            raise serializers.ValidationError("Both email and password are required")

        try:
            # Check if user exists with the email
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError("Invalid credentials")

        # Authenticate using the username (which is set as email here)
        user = authenticate(username=user.username, password=password)
        if not user:
            raise serializers.ValidationError("Invalid credentials")

        refresh = self.get_token(user)

        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'username': user.username,
            'email': user.email,
            'role': user.role,
        }

    def get_fields(self):
        fields = super().get_fields()

        # Replace the 'username' field with 'email' in the serializer
        fields['email'] = serializers.EmailField()

        # Remove 'username' field from the serializer because we are using 'email' instead
        if 'username' in fields:
            del fields['username']

        return fields

User = get_user_model()

class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    new_password = serializers.CharField(min_length=8, write_only=True)
    confirm_password = serializers.CharField(min_length=8, write_only=True)

    def validate(self, attrs):
        if attrs["new_password"] != attrs["confirm_password"]:
            raise serializers.ValidationError("Passwords do not match.")
        return attrs

    def save(self):
        email = self.validated_data["email"]
        new_password = self.validated_data["new_password"]

        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError("No user found with this email.")

        user.set_password(new_password)
        user.email_verification_uuid = None  # Optionally clear verification UUID
        user.is_active = True  # Optionally activate user
        user.save()
        return user

