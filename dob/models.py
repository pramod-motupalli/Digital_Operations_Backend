from django.contrib.auth.models import AbstractUser
from django.db import models
import uuid
class CustomUser(AbstractUser):
    ROLE_CLIENT      = 'client'
    ROLE_MANAGER     = 'manager'
    ROLE_TEAM_LEAD   = 'team_lead'
    ROLE_SPOC        = 'spoc'
    ROLE_ACCOUNTANT  = 'accountant'
    ROLE_TEAM_MEMBER = 'team_member'

    ROLE_CHOICES = [
        (ROLE_CLIENT,      'Client'),
        (ROLE_MANAGER,     'Manager'),
        (ROLE_TEAM_LEAD,   'Team Lead'),
        (ROLE_SPOC,        'SPOC'),
        (ROLE_ACCOUNTANT,  'Accountant'),
        (ROLE_TEAM_MEMBER, 'Team Member'),
    ]

    
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=150, unique=True)
    first_name = models.CharField(max_length=30, blank=True)   
    last_name = models.CharField(max_length=30, blank=True)   
    # In your CustomUser model
    is_email_verified = models.BooleanField(default=False)
    email_verification_token = models.CharField(max_length=64, blank=True, null=True)
    email_verification_uuid = models.UUIDField(default=uuid.uuid4, unique=True, null=True, blank=True)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default=ROLE_CLIENT)
    manager = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True, related_name='subordinates')
    team_lead = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True, related_name='team_members')

    def __str__(self):
        return f"{self.username} ({self.get_role_display()})"

class ClientProfile(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='client_profile')
    company_name = models.CharField(max_length=255)
    contact_number = models.CharField(max_length=20, blank=True)

    def __str__(self):
        return f"ClientProfile({self.user.username})"

class SPOCProfile(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='spoc_profile')
    department = models.CharField(max_length=100)

    def __str__(self):
        return f"SPOCProfile({self.user.username})"

class AccountantProfile(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='accountant_profile')
    certification = models.CharField(max_length=100, blank=True)

    def __str__(self):
        return f"AccountantProfile({self.user.username})"

class Team(models.Model):
    name = models.CharField(max_length=100, unique=True)
    manager = models.ForeignKey(CustomUser, on_delete=models.CASCADE, limit_choices_to={'role': CustomUser.ROLE_MANAGER}, related_name='managed_teams')
    team_lead = models.ForeignKey(CustomUser, on_delete=models.CASCADE, limit_choices_to={'role': CustomUser.ROLE_TEAM_LEAD}, related_name='led_teams')

    def __str__(self):
        return self.name

class TeamMembership(models.Model):
    team = models.ForeignKey(Team, on_delete=models.CASCADE, related_name='memberships')
    member = models.ForeignKey(CustomUser, on_delete=models.CASCADE, limit_choices_to={'role': CustomUser.ROLE_TEAM_MEMBER}, related_name='team_memberships')

    class Meta:
        unique_together = ('team', 'member')

    def __str__(self):
        return f"{self.member.username} in {self.team.name}"

class Plan(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    duration_days = models.PositiveIntegerField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} - ${self.price} / {self.duration_days} days"

class ClientPlan(models.Model):
    client = models.ForeignKey(ClientProfile, on_delete=models.CASCADE, related_name='plans')
    plan = models.ForeignKey(Plan, on_delete=models.CASCADE, related_name='client_plans')
    start_date = models.DateField()
    end_date = models.DateField()
    is_active = models.BooleanField(default=True)

    class Meta:
        unique_together = ('client', 'plan')

    def __str__(self):
        return f"{self.client.user.username} - {self.plan.name}"

class Website(models.Model):
    client = models.ForeignKey(ClientProfile, on_delete=models.CASCADE, related_name='websites')
    url = models.URLField(unique=True)
    host_provider = models.CharField(max_length=255)
    expiry_date = models.DateField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Website({self.url}) for {self.client.user.username}"
