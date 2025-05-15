from django.contrib import admin
from django.urls import path, include
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path('admin/', admin.site.urls),

    # Include user routes (register and token are in dob.urls)
    path('api/users/', include('dob.urls')),

    # JWT refresh token endpoint
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]
