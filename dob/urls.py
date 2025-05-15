from django.urls import path
from .views import RegisterClientView, MyTokenObtainPairView

urlpatterns = [
    path('register/', RegisterClientView.as_view(), name='register_client'),
    path('token/', MyTokenObtainPairView.as_view(), name='token_obtain_pair'),
]
