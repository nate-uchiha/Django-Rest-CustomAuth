from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group

from rest_framework import serializers

from phonenumber_field.modelfields import PhoneNumberField

from .models import Profile

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
    phone_number = serializers.CharField(
        validators=PhoneNumberField().validators
    )

    def _validate_email(self, email):
        try:
            user = UserModel.objects.get(email__iexact=email)
            return False
        except UserModel.DoesNotExist:
            return True

    def _validate_password(self, password1, password2):
        if password1 == password2:
            return True
        else:
            return False    
        
    def _validate_phone(self, phone_number):
        try:
            user = UserModel.objects.get(phone_number=phone_number)
            return False
        except UserModel.DoesNotExist:
            return True

    def _create_user(self, data):
        user = UserModel.objects.create_user(data['email'], data['first_name'], data['last_name'], data['password1'])
        user.phone_number = data['phone_number']
        user.save()
        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255, allow_blank=False, required=True)
    password = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password', 'placeholder': 'Password'}
    )


class GroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = Group
        fields = ('name',)

class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = ('avatar',)

class UserDetailsSerializer(serializers.ModelSerializer):
    groups = GroupSerializer(many=True, read_only=True)
    profile = ProfileSerializer()
    class Meta:
        model = UserModel
        fields = ('email', 'first_name', 'last_name', 'last_login', 'groups', 'profile')