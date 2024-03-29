from django.contrib import admin
from django.contrib.auth.models import Group
from django.contrib.auth.admin import UserAdmin

from .forms import CustomUserChangeForm, CustomUserCreationForm
from .models import CustomUser, Profile

# Register your models here.
class CustomUserUserAdmin(UserAdmin):
    form = CustomUserChangeForm
    add_form = CustomUserCreationForm
    
    list_display = ('email', 'first_name', 'last_name', 'phone_number', 'is_email_verified', 'is_active', 'is_admin', 'last_login')
    list_filter = ('is_admin',)
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal info', {'fields': ('first_name', 'last_name', 'phone_number')}),
        ('Permissions', {'fields': ('is_admin', 'is_superuser', 'is_email_verified', 'is_active', 'user_permissions',),}),
        ('Groups', {'fields': ('groups', ),}),
    )

    add_fieldsets = (
        (None, {
            'classes': ('Wide',),
            'fields': ('email', 'first_name', 'last_name', 'password1', 'password2',),
        }),
    )
    search_fields = ('first_name',)
    ordering = ('email',)
    filter_horizontal = ()


admin.site.register(CustomUser, CustomUserUserAdmin)
admin.site.register(Profile)