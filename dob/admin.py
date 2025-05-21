from django.contrib import admin
from .models import CustomUser, ClientProfile,TeamLeadProfile,ManagerProfile,StaffProfile,AccountantProfile

admin.site.register(CustomUser)
admin.site.register(ClientProfile)
admin.site.register(TeamLeadProfile)
admin.site.register(ManagerProfile)
admin.site.register(StaffProfile)
admin.site.register(AccountantProfile)
