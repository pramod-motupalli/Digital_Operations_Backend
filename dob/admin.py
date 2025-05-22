from django.contrib import admin
from .models import CustomUser, ClientProfile,TeamLeadProfile,ManagerProfile,StaffProfile,AccountantProfile
from .models import Plan, DomainHosting, Accountant, PlanRequest

admin.site.register(Plan)
admin.site.register(DomainHosting)
admin.site.register(Accountant)
admin.site.register(PlanRequest)

admin.site.register(CustomUser)
admin.site.register(ClientProfile)
admin.site.register(TeamLeadProfile)
admin.site.register(ManagerProfile)
admin.site.register(StaffProfile)
admin.site.register(AccountantProfile)
