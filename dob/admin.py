from django.contrib import admin
from .models import *

admin.site.register(Plan)
admin.site.register(DomainHosting)
admin.site.register(PlanRequest)

admin.site.register(CustomUser)
admin.site.register(ClientProfile)
admin.site.register(TeamLeadProfile)
admin.site.register(ManagerProfile)
admin.site.register(StaffProfile)
admin.site.register(AccountantProfile)
admin.site.register(Workspace)
admin.site.register(Task)
admin.site.register(WorkflowStep)
admin.site.register(WorkItem)
admin.site.register(TaskAssignment)
admin.site.register(Notification)