from django.conf.urls import url
from users.views import UserRegisterView, LoginView, UserDetailsView, PasswordResetView, PasswordResetConfimView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

urlpatterns = [
    url(r'signup/', UserRegisterView.as_view(), name='register'),
    url(r'login/', LoginView.as_view(), name='login'),
    url(r'^refresh_token/', TokenRefreshView.as_view(), name='token_refresh'),
    url(r'^passwordReset/', PasswordResetView.as_view(), name='pasword_reset'),
    url(r'^passwordResetConfirm/', PasswordResetConfimView.as_view(), name='pasword_reset_confirm'),
    url(r'^me/$', UserDetailsView.as_view(), name='user_details')
]