from django.conf.urls import url
from users.views import UserRegisterView, LoginView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

urlpatterns = [
    url(r'signup/', UserRegisterView.as_view(), name='register'),
    url(r'login/', LoginView.as_view(), name='login'),
    url(r'^refresh_token', TokenRefreshView.as_view(), name='token_refresh')
]