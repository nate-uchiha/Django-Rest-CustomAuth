from django.conf.urls import url
from users.views import UserRegisterView

urlpatterns = [
    url(r'signup/', UserRegisterView.as_view(), name='register'),
]