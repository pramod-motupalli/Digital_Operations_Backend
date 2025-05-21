from rest_framework import serializers
from django.contrib.auth import authenticate, get_user_model
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from .models import CustomUser, ClientProfile, TeamLeadProfile, StaffProfile, AccountantProfile,ManagerProfile

CustomUser = get_user_model()
User = get_user_model()


# 1️⃣ Client Registration Serializer
class ClientRegistrationSerializer(serializers.ModelSerializer):
    phone_number = serializers.CharField(write_only=True)

    class Meta:
        model = CustomUser
        fields = ['email', 'username', 'first_name', 'last_name', 'password', 'phone_number']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        phone_number = validated_data.pop('phone_number')
        password = validated_data.pop('password')

        user = CustomUser.objects.create_user(
            **validated_data,
            password=password,
            role=CustomUser.ROLE_CLIENT
        )

        ClientProfile.objects.create(
            user=user,
            company_name="N/A",
            contact_number=phone_number
        )

        return user

class ManagerProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['email', 'username', 'first_name', 'last_name', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        validated_data.pop('user', None)  # since you're creating user below
        user = CustomUser.objects.create_user(
            **validated_data,
            role=CustomUser.ROLE_MANAGER,
        )
        user.is_active = False
        user.save()

        # Create ManagerProfile for the user
        ManagerProfile.objects.create(user=user)
        return user


class TeamLeadRegistrationSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(write_only=True)
    username = serializers.CharField(write_only=True)
    first_name = serializers.CharField(write_only=True)
    last_name = serializers.CharField(write_only=True)
    password = serializers.CharField(write_only=True)
    manager_email = serializers.CharField(write_only=True)  # Accept manager username

    class Meta:
        model = TeamLeadProfile
        fields = [
            'email', 'username', 'first_name', 'last_name', 'password',
            'designation', 'is_spoc', 'manager_email'
        ]

    def create(self, validated_data):
        manager_email = validated_data.pop('manager_email')

        try:
            # Get the manager user with the specified username and role
            manager_user = CustomUser.objects.get(email=manager_email, role=CustomUser.ROLE_MANAGER)
            # Get the manager profile related to that user
            manager_profile = manager_user.manager_profile
        except (CustomUser.DoesNotExist, ManagerProfile.DoesNotExist):
            raise serializers.ValidationError({'manager_username': 'Manager not found or invalid role.'})

        # Extract user creation fields from validated_data
        email = validated_data.pop('email')
        username = validated_data.pop('username')
        first_name = validated_data.pop('first_name')
        last_name = validated_data.pop('last_name')
        password = validated_data.pop('password')

        # Create the Team Lead user with the role TEAM_LEAD
        user = CustomUser.objects.create_user(
            email=email,
            username=username,
            first_name=first_name,
            last_name=last_name,
            password=password,
            role=CustomUser.ROLE_TEAM_LEAD
        )
        user.is_active = False  # Set inactive initially
        user.save()

        # Create and return the TeamLeadProfile linking the user and the manager profile
        return TeamLeadProfile.objects.create(
            user=user,
            parent=manager_profile,
            **validated_data
        )


class StaffRegistrationSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(write_only=True)
    username = serializers.CharField(write_only=True)
    first_name = serializers.CharField(write_only=True)
    last_name = serializers.CharField(write_only=True)
    password = serializers.CharField(write_only=True)
    team_lead_username = serializers.CharField(write_only=True)  #  link via username

    class Meta:
        model = StaffProfile
        fields = [
            'email', 'username', 'first_name', 'last_name', 'password',
            'designation', 'team_lead_username'
        ]

    def create(self, validated_data):
        team_lead_username = validated_data.pop('team_lead_username')

        try:
            team_lead_user = CustomUser.objects.get(username=team_lead_username, role=CustomUser.ROLE_TEAM_LEAD)
            team_lead_profile = team_lead_user.teamlead_profile
        except (CustomUser.DoesNotExist, TeamLeadProfile.DoesNotExist):
            raise serializers.ValidationError({'team_lead_username': 'Team lead not found or invalid role.'})

        # Extract CustomUser fields
        email = validated_data.pop('email')
        username = validated_data.pop('username')
        first_name = validated_data.pop('first_name')
        last_name = validated_data.pop('last_name')
        password = validated_data.pop('password')

        # Create CustomUser with STAFF role
        user = CustomUser.objects.create_user(
            email=email,
            username=username,
            first_name=first_name,
            last_name=last_name,
            password=password,
            role=CustomUser.ROLE_TEAM_MEMBER  # or ROLE_STAFF if defined
        )
        user.is_active = False
        user.save()

        return StaffProfile.objects.create(
            user=user,
            team_lead=team_lead_profile,
            **validated_data
        )
    

class AccountantRegistrationSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(write_only=True)
    username = serializers.CharField(write_only=True)
    first_name = serializers.CharField(write_only=True)
    last_name = serializers.CharField(write_only=True)
    password = serializers.CharField(write_only=True)
    parent_username = serializers.CharField(write_only=True)  # Manager's username

    class Meta:
        model = AccountantProfile
        fields = [
            'email', 'username', 'first_name', 'last_name',
            'password', 'parent_username'
        ]

    def create(self, validated_data):
        parent_username = validated_data.pop('parent_username')

        try:
            manager_user = CustomUser.objects.get(username=parent_username, role=CustomUser.ROLE_MANAGER)
            managerprofile = manager_user.manager_profile
        except (CustomUser.DoesNotExist, ManagerProfile.DoesNotExist):
            raise serializers.ValidationError({'parent_username': 'Manager not found or invalid role.'})

        # Create user
        user = CustomUser.objects.create_user(
            email=validated_data.pop('email'),
            username=validated_data.pop('username'),
            first_name=validated_data.pop('first_name'),
            last_name=validated_data.pop('last_name'),
            password=validated_data.pop('password'),
            role=CustomUser.ROLE_ACCOUNTANT
        )
        user.is_active = False
        user.save()

        return AccountantProfile.objects.create(
            user=user,
            parent=managerprofile
        )




# 3️⃣ Token (JWT) Serializer with Email Login
class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    username_field = 'email'

    def validate(self, attrs):
        email = attrs.get("email")
        password = attrs.get("password")

        if not email or not password:
            raise serializers.ValidationError("Both email and password are required.")

        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError("Invalid credentials.")

        user = authenticate(username=user.username, password=password)
        if not user:
            raise serializers.ValidationError("Invalid credentials.")

        refresh = self.get_token(user)

        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'username': user.username,
            'email': user.email,
            'role': user.role,
            'is_email_verified': user.is_email_verified,
        }

    def get_fields(self):
        fields = super().get_fields()
        fields['email'] = serializers.EmailField()
        if 'username' in fields:
            del fields['username']
        return fields


# 4️⃣ Reset Password Serializer
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
        user.email_verification_uuid = None
        user.is_active = True
        user.save()
        return user
