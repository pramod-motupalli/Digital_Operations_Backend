from django.db import models

# Create your models here.
from django.contrib.auth.models import AbstractUser
from django.db import models

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
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default=ROLE_CLIENT)
    manager = models.ForeignKey(
        'self', on_delete=models.SET_NULL, null=True, blank=True,
        related_name='subordinates'
    )
    team_lead = models.ForeignKey(
        'self', on_delete=models.SET_NULL, null=True, blank=True,
        related_name='team_members'
    )

    def _str_(self):
        return f"{self.username} ({self.get_role_display()})"

class ClientProfile(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='client_profile')
    company_name = models.CharField(max_length=255)
    contact_number = models.CharField(max_length=20, blank=True)

    def _str_(self):
        return f"ClientProfile({self.user.username})"

class SPOCProfile(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='spoc_profile')
    department = models.CharField(max_length=100)

    def _str_(self):
        return f"SPOCProfile({self.user.username})"

class AccountantProfile(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='accountant_profile')
    certification = models.CharField(max_length=100, blank=True)

    def _str_(self):
        return f"AccountantProfile({self.user.username})"

class Team(models.Model):
    name = models.CharField(max_length=100, unique=True)
    manager = models.ForeignKey(
        CustomUser, on_delete=models.CASCADE,
        limit_choices_to={'role': CustomUser.ROLE_MANAGER},
        related_name='managed_teams'
    )
    team_lead = models.ForeignKey(
        CustomUser, on_delete=models.CASCADE,
        limit_choices_to={'role': CustomUser.ROLE_TEAM_LEAD},
        related_name='led_teams'
    )

    def _str_(self):
        return self.name

class TeamMembership(models.Model):
    team = models.ForeignKey(Team, on_delete=models.CASCADE, related_name='memberships')
    member = models.ForeignKey(
        CustomUser, on_delete=models.CASCADE,
        limit_choices_to={'role': CustomUser.ROLE_TEAM_MEMBER},
        related_name='team_memberships'
    )

    class Meta:
        unique_together = ('team', 'member')

    def _str_(self):
        return f"{self.member.username} in {self.team.name}"