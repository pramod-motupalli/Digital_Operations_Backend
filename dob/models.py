from django.db import models
from django.contrib.auth.models import AbstractUser
from datetime import datetime, date, timedelta
import uuid

# ------------------- Custom User and Role Models -------------------

class CustomUser(AbstractUser):
    ROLE_CLIENT      = 'client'
    ROLE_MANAGER     = 'manager'
    ROLE_TEAM_LEAD   = 'team_lead'
    ROLE_SPOC        = 'spoc'
    ROLE_ACCOUNTANT  = 'accountant'
    ROLE_TEAM_MEMBER = 'team_member'

    ROLE_CHOICES = [
        (ROLE_CLIENT, 'Client'),
        (ROLE_MANAGER, 'Manager'),
        (ROLE_TEAM_LEAD, 'Team Lead'),
        (ROLE_SPOC, 'SPOC'),
        (ROLE_ACCOUNTANT, 'Accountant'),
        (ROLE_TEAM_MEMBER, 'Team Member'),
    ]

    email = models.EmailField(unique=True)
    username = models.CharField(max_length=150, unique=True)
    first_name = models.CharField(max_length=30, blank=True)
    last_name = models.CharField(max_length=30, blank=True)
    is_email_verified = models.BooleanField(default=False)
    is_visited = models.BooleanField(default=False)
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


class ManagerProfile(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='manager_profile')
    parent = models.CharField(max_length=100, default="Null", null=True)

    def __str__(self):
        return f"ManagerProfile({self.user.username})"


class TeamLeadProfile(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='teamlead_profile', primary_key=True)
    designation = models.CharField(max_length=100, default="teamlead")
    is_spoc = models.BooleanField(default=False)
    parent = models.ForeignKey(ManagerProfile, on_delete=models.SET_NULL, null=True)

    def __str__(self):
        return f"TeamLeadProfile({self.user.username})"


class StaffProfile(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, primary_key=True)
    designation = models.TextField(blank=True)
    team_lead = models.ForeignKey(TeamLeadProfile, on_delete=models.SET_NULL, null=True)

    def __str__(self):
        return f"StaffProfile({self.user.username})"

    @property
    def tasks(self):
        return self.assigned_tasks.all()



class AccountantProfile(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    parent = models.ForeignKey(ManagerProfile, on_delete=models.SET_NULL, null=True)

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

# ------------------- Plan & Domain Integration (updated for CustomUser) -------------------

class Plan(models.Model):
    title = models.CharField(max_length=100)
    price = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    billing = models.CharField(max_length=10, choices=[('monthly', 'Monthly'), ('yearly', 'Yearly')])
    features = models.JSONField()

    client = models.ForeignKey('CustomUser', on_delete=models.SET_NULL, null=True, blank=True, related_name='plans')  # FK here

    payment_status = models.CharField(
        max_length=20,
        choices=[('Pending', 'Pending'), ('Done', 'Done'), ('Failed', 'Failed')],
        default='Done'
    )

    payment_is_approved = models.BooleanField(null=True, blank=True, default=None)
    is_workspace_activated = models.BooleanField(null=True, blank=True, default=None)

    def __str__(self):
        return f"{self.title} ({self.payment_status})"



class DomainHosting(models.Model):
    plan = models.ForeignKey('Plan', on_delete=models.CASCADE, related_name='domain_hostings')
    client = models.ForeignKey('CustomUser', on_delete=models.SET_NULL, null=True, blank=True, related_name='domain_hostings')  # FK here

    assigned_to = models.CharField(max_length=100, blank=True, null=True)
    domain_name = models.CharField(max_length=100, blank=True, null=True)
    domain_provider = models.CharField(max_length=100, blank=True, null=True)
    domain_account = models.CharField(max_length=100, blank=True, null=True)
    domain_expiry = models.DateField(blank=True, null=True)
    hosting_provider = models.CharField(max_length=100, blank=True, null=True)
    hosting_provider_name = models.CharField(max_length=100, blank=True, null=True)
    hosting_expiry = models.DateField(blank=True, null=True)

    status = models.CharField(
        max_length=10,
        choices=[('running', 'Running'), ('expired', 'Expired'), ('expiring', 'Expiring')],
        default='running',
    )

    hd_payment_status = models.CharField(
        max_length=15,
        choices=[('pending', 'Pending'), ('done', 'Done')],
        default='pending',
    )

    def save(self, *args, **kwargs):
        today = date.today()

        if isinstance(self.hosting_expiry, str):
            try:
                self.hosting_expiry = datetime.strptime(self.hosting_expiry, "%Y-%m-%d").date()
            except ValueError:
                raise ValueError("Invalid date format for hosting_expiry. Expected YYYY-MM-DD.")

        if self.hosting_expiry:
            if self.hosting_expiry < today:
                self.status = 'expired'
            elif self.hosting_expiry <= today + timedelta(days=30):
                self.status = 'expiring'
            else:
                self.status = 'running'

        super().save(*args, **kwargs)



class PlanRequest(models.Model):
    plan = models.ForeignKey(Plan, on_delete=models.CASCADE)
    client = models.ForeignKey(CustomUser, null=True, blank=True, on_delete=models.SET_NULL, related_name='client_requests')
    submitted_at = models.DateTimeField(auto_now_add=True)
    is_approved = models.BooleanField(null=True)
    overridden_price = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)

    def get_price(self):
        return self.overridden_price if self.overridden_price is not None else self.plan.price

    def __str__(self):
        return f"Request for {self.plan.title} by {self.client.username if self.client else 'Unknown'}"


class PaymentRequest(models.Model):
    plan_request = models.ForeignKey(PlanRequest, on_delete=models.CASCADE, related_name='payment_requests')
    price = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)


class Workspace(models.Model):
    client = models.ForeignKey(CustomUser, null=True, blank=True, on_delete=models.CASCADE, related_name='workspace')
    workspace_name = models.CharField(max_length=255)
    description = models.TextField()
    assign_staff = models.ForeignKey(CustomUser, related_name='assigned_staff', on_delete=models.CASCADE, null=True, blank=True)
    assign_spoc = models.ForeignKey(CustomUser, related_name='assigned_spoc', on_delete=models.CASCADE, null=True, blank=True)
    hd_maintenance = models.ForeignKey(CustomUser, related_name='assigned_hd', on_delete=models.CASCADE, null=True, blank=True)
    is_workspace_activated = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.workspace_name
    
from django.conf import settings

class Task(models.Model):
    # title = models.CharField(max_length=100)
    current_step_index = models.IntegerField(default=0)
    workspace = models.ForeignKey(
        'Workspace',
        on_delete=models.CASCADE,
        related_name='tasks'
    )

    domain_hosting = models.ForeignKey(
        'DomainHosting',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='tasks'
    )

    client = models.ForeignKey(
        'ClientProfile',
        on_delete=models.CASCADE,
        related_name='tasks'
    )

    assigned_staff = models.ManyToManyField(
        'StaffProfile',
        through='TaskAssignment',
        related_name='tasks_participating_in'
    )

    flow_or_hours = models.CharField(  # This can be renamed based on your real need
        max_length=255,
        blank=True
    )

    workhours = models.FloatField(  # Use IntegerField if you expect only whole hours
        null=True,
        blank=True
    )

    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)

    status = models.CharField(
        max_length=50,
        choices=[
            ('pending', 'Pending'),
            ('in_scope', 'In Scope'),
            ('out_of_scope', 'Out of Scope'),
        ],
        default='pending'
    )
    
    due_date = models.DateField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    raised_to_client = models.BooleanField(default=False)
    ACCEPTANCE_CHOICES = [
        ('pending', 'Pending'),
        ('accepted', 'Accepted'),
        ('rejected', 'Rejected'),
    ]
    client_acceptance_status = models.CharField(
        max_length=10,
        choices=ACCEPTANCE_CHOICES,
        default='pending',
    )
    rejection_reason = models.TextField(blank=True, null=True)
    PAYMENT_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('done', 'Done'),
        ('unavailable', 'Unavailable'),
    ]
    payment_status = models.CharField(
        max_length=20,
        choices=PAYMENT_STATUS_CHOICES,
        default='pending',
    )
    raised_to_spoc = models.BooleanField(default=False)
    deadline = models.DateField(null=True, blank=True)
    STATUS_CHOICES = [
        ('backlog', 'Backlog'),
        ('todo', 'TO-DO'),
        ('processing', 'Processing'),
        ('review', 'Review'),
        ('done', 'Done'),
    ]

    task_status = models.CharField(
        max_length=20,
        
        default='backlog',
    )
    def __str__(self):
        return self.title
# models.py
class TaskAssignment(models.Model):
    task = models.ForeignKey(Task, on_delete=models.CASCADE)
    staff_member = models.ForeignKey('StaffProfile', on_delete=models.CASCADE)
    designation_at_assignment = models.CharField(max_length=100, blank=True) # e.g., "Developer", "Designer"
    time_estimation = models.CharField(max_length=20, blank=True, null=True) # Or DurationField
    member_deadline = models.DateField(null=True, blank=True)
    STATUS_CHOICES = [
        ('backlog', 'Backlog'),
        ('todo', 'To Do'),
        ('processing', 'Processing'),
        ('review', 'Under Review'),
        ('done', 'Done'),
    ]
    REVIEW_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('redo', 'Redo Required'),
        ('completed', 'Review Completed'),
    ]
    order = models.IntegerField(default=0)
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='backlog'  # default value
    )
    review_status = models.CharField(
        max_length=20,
        choices=REVIEW_STATUS_CHOICES,
        default='pending'  # default value
    )
    # ... other assignment-specific fields


class WorkItem(models.Model):
    title = models.CharField(max_length=100)
    current_step_index = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    client = models.ForeignKey('ClientProfile', on_delete=models.CASCADE, related_name='work_items')
    domain_hosting = models.ForeignKey('DomainHosting', on_delete=models.CASCADE, related_name='work_items')

class WorkflowStep(models.Model):
    STATUS_CHOICES = [
        ('backlog', 'Backlog'),
        ('todo', 'To Do'),
        ('processing', 'Processing'),
        ('review', 'Under Review'),
        ('done', 'Done'),
        
    ]

    REVIEW_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('redo', 'Redo Required'),
        ('completed', 'Review Completed'),
    ]
    

    work_item = models.ForeignKey(WorkItem, related_name='workflow_steps', on_delete=models.CASCADE)
    role = models.CharField(max_length=50)
    user = models.ForeignKey(CustomUser, null=True, on_delete=models.SET_NULL)
    order = models.IntegerField()
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='backlog')
    review_status = models.CharField(max_length=20, choices=REVIEW_STATUS_CHOICES, null=True, blank=True)

    completed_at = models.DateTimeField(null=True, blank=True)

class Notification(models.Model):
    from_user = models.ForeignKey(
        CustomUser,
        on_delete=models.CASCADE,
        related_name='sent_notifications'
    )
    to_users = models.ManyToManyField(
        CustomUser,
        related_name='received_notifications'
    )
    subject = models.CharField(max_length=255)
    message = models.TextField()
    is_read = models.BooleanField(default=False)  # Shared read status
    created_at = models.DateTimeField(auto_now_add=True)

    def str(self):
        return f"{self.subject} | From: {self.from_user.username}"

    class Meta:
        ordering = ['-created_at']