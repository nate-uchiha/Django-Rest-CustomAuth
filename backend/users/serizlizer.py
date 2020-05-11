from django.contrib.auth import get_user_model

from rest_framework import serializers

UserModel = get_user_model()

class UserRegisterSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255, allow_blank=False, required=True)
    password1 = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password', 'placeholder': 'Password'}
    )
    password2 = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password', 'placeholder': 'Confirm Password'}
    )
    first_name = serializers.CharField(max_length=30, required=True)
    last_name = serializers.CharField(max_length=30, required=True)
    phone_number = serializers.CharField()

    def _validate_email(self, email):
        try:
            user = UserModel.objects.get(email_iexact=email)
            return False
        except UserModel.DoesNotExist:
            return True

    def _validate_password(self, password1, password2):
        if password1 == password2:
            return True
        else:
            return False    

    def _create_user(data):
        print("data is create_user: ", data)