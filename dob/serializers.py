from rest_framework import serializers
from django.contrib.auth import authenticate, get_user_model
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.tokens import RefreshToken, TokenError

from .models import *

CustomUser = get_user_model()

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


# 2️⃣ Manager Registration Serializer
class ManagerProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['email', 'username', 'first_name', 'last_name', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = CustomUser.objects.create_user(
            **validated_data,
            role=CustomUser.ROLE_MANAGER
        )
        user.is_active = True
        user.save()

        ManagerProfile.objects.create(user=user)
        return user


# 3️⃣ Team Lead Registration Serializer
class TeamLeadRegistrationSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(write_only=True)
    username = serializers.CharField(write_only=True)
    first_name = serializers.CharField(write_only=True)
    last_name = serializers.CharField(write_only=True)
    password = serializers.CharField(write_only=True)
    manager_email = serializers.CharField(write_only=True)

    class Meta:
        model = TeamLeadProfile
        fields = [
            'email', 'username', 'first_name', 'last_name', 'password',
            'designation', 'is_spoc', 'manager_email'
        ]

    def create(self, validated_data):
        manager_email = validated_data.pop('manager_email')

        try:
            manager_user = CustomUser.objects.get(email=manager_email, role=CustomUser.ROLE_MANAGER)
            manager_profile = manager_user.manager_profile
        except (CustomUser.DoesNotExist, ManagerProfile.DoesNotExist):
            raise serializers.ValidationError({'manager_email': 'Manager not found or invalid role.'})

        email = validated_data.pop('email')
        username = validated_data.pop('username')
        first_name = validated_data.pop('first_name')
        last_name = validated_data.pop('last_name')
        password = validated_data.pop('password')

        user = CustomUser.objects.create_user(
            email=email,
            username=username,
            first_name=first_name,
            last_name=last_name,
            password=password,
            role=CustomUser.ROLE_TEAM_LEAD
        )
        user.is_active = True
        user.save()

        return TeamLeadProfile.objects.create(
            user=user,
            parent=manager_profile,
            **validated_data
        )

from django.utils.text import slugify

class TeamLeadAutoRegistrationSerializer(serializers.ModelSerializer):
    name = serializers.CharField(write_only=True)
    email = serializers.EmailField(write_only=True)
    designation = serializers.CharField()

    class Meta:
        model = TeamLeadProfile
        fields = ['name', 'email', 'designation']  # Removed is_spoc from input

    def create(self, validated_data):
        request = self.context.get('request')
        manager_user = request.user

        if not hasattr(manager_user, 'manager_profile'):
            raise serializers.ValidationError('Only a manager can register a team lead.')

        manager_profile = manager_user.manager_profile

        name = validated_data.pop('name')
        email = validated_data.pop('email')
        designation = validated_data.pop('designation')

        # Split name into first and last name
        name_parts = name.strip().split()
        if len(name_parts) >= 2:
            first_name = name_parts[0]
            last_name = " ".join(name_parts[1:])
        else:
            first_name = last_name = name

        # Generate unique username
        base_username = slugify(name.replace(" ", "").lower())
        username = base_username
        counter = 1
        while CustomUser.objects.filter(username=username).exists():
            username = f"{base_username}{counter}"
            counter += 1

        # Generate default password
        team_lead_count = CustomUser.objects.filter(role=CustomUser.ROLE_TEAM_LEAD).count()
        password = f"teamlead{team_lead_count + 1}"

        # Create user
        user = CustomUser.objects.create_user(
            email=email,
            username=username,
            first_name=first_name,
            last_name=last_name,
            password=password,
            role=CustomUser.ROLE_TEAM_LEAD
        )
        user.is_active = True
        user.save()

        # Create TeamLeadProfile with is_spoc set to False
        return TeamLeadProfile.objects.create(
            user=user,
            parent=manager_profile,
            designation=designation,
            is_spoc=False  # Set default here
        )



# 4️⃣ Staff Registration Serializer
class StaffRegistrationSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(write_only=True)
    username = serializers.CharField(write_only=True)
    first_name = serializers.CharField(write_only=True)
    last_name = serializers.CharField(write_only=True)
    password = serializers.CharField(write_only=True)
    team_lead_username = serializers.CharField(write_only=True)

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

        email = validated_data.pop('email')
        username = validated_data.pop('username')
        first_name = validated_data.pop('first_name')
        last_name = validated_data.pop('last_name')
        password = validated_data.pop('password')

        user = CustomUser.objects.create_user(
            email=email,
            username=username,
            first_name=first_name,
            last_name=last_name,
            password=password,
            role=CustomUser.ROLE_TEAM_MEMBER
        )
        user.is_active = True
        user.save()

        return StaffProfile.objects.create(
            user=user,
            team_lead=team_lead_profile,
            **validated_data
        )


# 5️⃣ Accountant Registration Serializer
class AccountantRegistrationSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(write_only=True)
    username = serializers.CharField(write_only=True)
    first_name = serializers.CharField(write_only=True)
    last_name = serializers.CharField(write_only=True)
    password = serializers.CharField(write_only=True)
    parent_username = serializers.CharField(write_only=True)

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
            manager_profile = manager_user.manager_profile
        except (CustomUser.DoesNotExist, ManagerProfile.DoesNotExist):
            raise serializers.ValidationError({'parent_username': 'Manager not found or invalid role.'})

        user = CustomUser.objects.create_user(
            email=validated_data.pop('email'),
            username=validated_data.pop('username'),
            first_name=validated_data.pop('first_name'),
            last_name=validated_data.pop('last_name'),
            password=validated_data.pop('password'),
            role=CustomUser.ROLE_ACCOUNTANT
        )
        user.is_active = True
        user.save()

        return AccountantProfile.objects.create(
            user=user,
            parent=manager_profile
        )

class CustomUserVisitedSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'username', 'email', 'is_visited']
        read_only_fields = ['id', 'username', 'email']

# 6️⃣ JWT Token Serializer (Email-based Login)

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
            'is_visited':user.is_visited,
        }

    def get_fields(self):
        fields = super().get_fields()
        fields['email'] = serializers.EmailField()
        if 'username' in fields:
            del fields['username']
        return fields

# 7️⃣ Refresh Token Serializer
class TokenRefreshSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    def validate(self, attrs):
        self.refresh = attrs['refresh']
        try:
            refresh_token = RefreshToken(self.refresh)
            return {'access': str(refresh_token.access_token)}
        except TokenError:
            raise serializers.ValidationError('Refresh token is invalid or expired')

# serializers.py
from rest_framework import serializers
from .models import CustomUser, TeamLeadProfile, StaffProfile, AccountantProfile


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'username', 'first_name', 'last_name', 'email', 'role']


class TeamLeadSerializer(serializers.ModelSerializer):
    name = serializers.SerializerMethodField()
    email = serializers.EmailField(source='user.email')
    username = serializers.SerializerMethodField()

    class Meta:
        model = TeamLeadProfile
        fields = ['name', 'email', 'username', 'designation', 'is_spoc']

    def get_name(self, obj):
        return f"{obj.user.first_name} {obj.user.last_name}".strip()

    def get_username(self, obj):
        return obj.user.username


class StaffSerializer(serializers.ModelSerializer):
    email = serializers.SerializerMethodField()
    name = serializers.SerializerMethodField()
    id = serializers.ReadOnlyField(source='user.id')
    class Meta:
        model = StaffProfile
        fields = ['id','team_lead','designation', 'email', 'name']

    def get_email(self, obj):
        return obj.user.email

    def get_name(self, obj):
        return f"{obj.user.first_name} {obj.user.last_name}".strip()

class AccountantSerializer(serializers.ModelSerializer):
    user = UserSerializer()

    class Meta:
        model = AccountantProfile
        fields = ['user']


# 8️⃣ Password Reset Serializer
class ResetPasswordSerializer(serializers.Serializer):
    new_password = serializers.CharField(min_length=8, write_only=True)
    confirm_password = serializers.CharField(min_length=8, write_only=True)

    def validate(self, attrs):
        if attrs["new_password"] != attrs["confirm_password"]:
            raise serializers.ValidationError("Passwords do not match.")
        return attrs

    def save(self):
        request = self.context.get("request")
        user = request.user

        new_password = self.validated_data["new_password"]
        user.set_password(new_password)
        user.email_verification_uuid = None
        user.is_active = True
        user.save()
        return user




class ClientUserSerializer(serializers.ModelSerializer):
    contact_number = serializers.SerializerMethodField()

    class Meta:
        model = CustomUser
        fields = ['id', 'username', 'email', 'contact_number']

    def get_contact_number(self, obj):
        try:
            return obj.client_profile.contact_number
        except ClientProfile.DoesNotExist:
            return None



# 9️⃣ Plan Serializer
class PlanSerializer(serializers.ModelSerializer):
    client = ClientUserSerializer(read_only=True)

    class Meta:
        model = Plan
        fields = '__all__'
        read_only_fields = ['client']


# 🔟 Domain Hosting Serializer
class DomainHostingSerializer(serializers.ModelSerializer):
    plan_title = serializers.CharField(source='plan.title', read_only=True)
    plan_price = serializers.DecimalField(source='plan.price', max_digits=10, decimal_places=2, read_only=True)
    client = ClientUserSerializer(read_only=True)
    class Meta:
        model = DomainHosting
        fields = '__all__'  # ✅ Keeps compatibility with other frontends
        read_only_fields = ['plan_title', 'plan_price', 'client']


# 1️⃣1️⃣ Plan Request Serializer
class PlanRequestSerializer(serializers.ModelSerializer):
    plan_title = serializers.CharField(source='plan.title', read_only=True)
    plan_features = serializers.JSONField(source='plan.features', read_only=True)
    client = ClientUserSerializer(read_only=True)
    plan_price = serializers.SerializerMethodField()

    class Meta:
        model = PlanRequest
        fields = '__all__'
        read_only_fields = ['plan_title', 'plan_features', 'client']

    def get_plan_price(self, obj):
        return obj.get_price()



# 1️⃣2️⃣ Payment Request Serializer
class PaymentRequestSerializer(serializers.ModelSerializer):
    price = serializers.SerializerMethodField()
    title = serializers.SerializerMethodField()

    class Meta:
        model = PaymentRequest
        fields = '__all__'  # add other fields you want here

    def get_price(self, obj):
        # Access the price from related plan
        if obj.plan_request and obj.plan_request.plan:
            return obj.plan_request.plan.price
        return None
    def get_title(self, obj):
        return obj.plan_request.plan.title if obj.plan_request and obj.plan_request.plan else None

    
class WorkspaceSerializer(serializers.ModelSerializer):
    client = serializers.PrimaryKeyRelatedField(queryset=CustomUser.objects.all())
    assign_spoc = serializers.PrimaryKeyRelatedField(queryset=CustomUser.objects.all())
    assign_staff = serializers.PrimaryKeyRelatedField(queryset=CustomUser.objects.all())
    hd_maintenance = serializers.PrimaryKeyRelatedField(queryset=CustomUser.objects.all())

    class Meta:
        model = Workspace
        fields = '__all__'

class TaskAssignmentSerializer(serializers.ModelSerializer):
    staff_member_id = serializers.PrimaryKeyRelatedField(
        queryset=StaffProfile.objects.all(),
        source='staff_member',
    )
    staff_member_name = serializers.SerializerMethodField()

    class Meta:
        model = TaskAssignment
        fields = [
            'id',
            'staff_member_id',
            'staff_member_name',
            'designation_at_assignment',
            'time_estimation',
            'member_deadline',
        ]

    def get_staff_member_name(self, obj):
        return obj.staff_member.user.username if obj.staff_member and obj.staff_member.user else None

class TaskSerializer(serializers.ModelSerializer):
    workspace_id = serializers.ReadOnlyField(source='workspace.id')
    workspace_name = serializers.ReadOnlyField(source='workspace.workspace_name')
    client_name = serializers.SerializerMethodField()
    domain_name = serializers.SerializerMethodField()

    # Nested assignments
    assignments = TaskAssignmentSerializer(source='taskassignment_set', many=True, required=False)
    # assigned_to_usernames = serializers.SerializerMethodField()
    class Meta:
        model = Task
        fields = [
            'id', 'workspace', 'workspace_id', 'workspace_name',
            'title', 'description', 'status', 'created_at',
            'client_name', 'domain_name',
            'assignments',  # ✅ nested list of assigned staff with metadata
            'flow_or_hours', 'workhours',
            'due_date', 'raised_to_client', 'client_acceptance_status',
            'rejection_reason', 'payment_status', 'raised_to_spoc', 'deadline','task_status'
        ]
        read_only_fields = [
            'id', 'workspace_id', 'workspace_name',
            'created_at', 'client_name', 'domain_name'
        ]

    def get_client_name(self, obj):
        return obj.client.user.username if obj.client and obj.client.user else None

    def get_domain_name(self, obj):
        return obj.domain_hosting.domain_name if obj.domain_hosting else None
    def get_assigned_to_usernames(self, obj):
        return [staff.user.username for staff in obj.assigned_staff.all()]




# your_app/serializers.py


from rest_framework import serializers
from .models import Task

class TaskDetailSerializer(serializers.ModelSerializer):
    workspace_id = serializers.ReadOnlyField(source='workspace.id')
    workspace_name = serializers.ReadOnlyField(source='workspace.workspace_name')
    assigned_to_username = serializers.SerializerMethodField()
    client_name = serializers.SerializerMethodField()
    domain_name = serializers.SerializerMethodField()
    raised_to_client = serializers.BooleanField()
    client_acceptance_status = serializers.CharField()
    payment_status = serializers.CharField()
    raised_to_spoc = serializers.BooleanField()

    class Meta:
        model = Task
        fields = ['id', 'workspace', 'workspace_id', 'workspace_name', 'title', 'description', 'status', 'created_at', 'assigned_to_username', 'client_name', 'domain_name', 'raised_to_client', 'client_acceptance_status', 'payment_status', 'rejection_reason', 'raised_to_spoc', 'due_date', 'deadline']
        read_only_fields = ['workspace', 'workspace_id', 'workspace_name', 'status', 'created_at']

    def get_workspace_name(self, obj):
        return getattr(obj.workspace, 'name', None)

    def get_domain_name(self, obj):
        return getattr(obj.domain_hosting, 'domain_name', None)

    def get_client_name(self, obj):
        client_profile = obj.client
        if client_profile and hasattr(client_profile, 'user'):
            user = client_profile.user
            # Return full name if available, otherwise username
            full_name = f"{user.first_name} {user.last_name}".strip()
            return full_name if full_name else user.username
        return "N/A"
    
    def get_assigned_to_username(self, obj):
        return [staff.user.username for staff in obj.assigned_staff.all()]


from rest_framework import serializers
from datetime import datetime
from django.utils.timezone import localtime
from .models import Task

from rest_framework import serializers
from django.utils.timezone import localtime
from datetime import datetime
from .models import Task, TaskAssignment


class TaskCardSerializer(serializers.ModelSerializer):
    workspaceName = serializers.CharField(source='workspace.name')
    column = serializers.SerializerMethodField()
    escalation = serializers.SerializerMethodField()
    assignees = serializers.SerializerMethodField()
    dateInfo = serializers.SerializerMethodField()
    timeInfo = serializers.SerializerMethodField()
    daysLeft = serializers.SerializerMethodField()
    comments = serializers.SerializerMethodField()
    files = serializers.SerializerMethodField()
    tags = serializers.SerializerMethodField()
    image = serializers.SerializerMethodField()

    class Meta:
        model = Task
        fields = [
            'id', 'column', 'workspaceName', 'priority', 'escalation', 'title',
            'description', 'image', 'assignees', 'dateInfo', 'timeInfo',
            'daysLeft', 'comments', 'files', 'tags'
        ]

    def get_column(self, obj):
        return obj.task_status.capitalize() if obj.task_status else "TO-DO"

    def get_escalation(self, obj):
        return obj.priority == 'High'

    def get_assignees(self, obj):
        """
        Return assigned staff members as avatar colors or initials.
        For now, simulate colors — but you can use obj.assigned_staff.all() or through model.
        """
        # Example using avatar colors (can be changed to names/photos)
        staff_qs = obj.assigned_staff.all()
        avatar_colors = ["#FF5733", "#FFC300", "#DAF7A6", "#C70039"]
        return avatar_colors[:staff_qs.count()]

    def get_dateInfo(self, obj):
        return obj.created_at.strftime("%d/%m/%y") if obj.created_at else ""

    def get_timeInfo(self, obj):
        return localtime(obj.created_at).strftime("%I:%M %p") if obj.created_at else ""

    def get_daysLeft(self, obj):
        if obj.deadline:
            days = (obj.deadline - datetime.now().date()).days
            return f"D-{days}" if days >= 0 else "Expired"
        return "D-N/A"

    def get_comments(self, obj):
        # Replace with real related comment count logic if available
        return obj.comments.count() if hasattr(obj, 'comments') else 0

    def get_files(self, obj):
        # Replace with real related files count if such a model exists
        return obj.files.count() if hasattr(obj, 'files') else 0

    def get_tags(self, obj):
        # Implement tags logic if there's a Tag model related to Task
        return [tag.name for tag in obj.tags.all()] if hasattr(obj, 'tags') else []

    def get_image(self, obj):
        # Optional: derive from related domain/client/workspace
        return "TASK_IMAGE_URL"

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'username', 'email']

class NotificationSerializer(serializers.ModelSerializer):
    from_user = UserSerializer()
    to_users = UserSerializer(many=True)

    class Meta:
        model = Notification
        fields = ['id', 'from_user', 'to_users', 'subject', 'message', 'is_read', 'created_at']