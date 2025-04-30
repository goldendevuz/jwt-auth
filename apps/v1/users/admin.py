from django import forms
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from import_export import resources
from import_export.admin import ImportExportModelAdmin
from django.utils.translation import gettext_lazy as _

from apps.v1.shared.admin import BaseAdmin
from .models import User, UserConfirmation


class UserResource(resources.ModelResource):
    class Meta:
        model = User


class UserConfirmationResource(resources.ModelResource):
    class Meta:
        model = UserConfirmation


# Custom form to exclude password field
class CustomUserForm(forms.ModelForm):
    class Meta:
        model = User
        exclude = ('password',)  # Exclude password from the form

@admin.register(User)
class UserAdmin(ImportExportModelAdmin, BaseAdmin):
    resource_classes = [UserResource]
    list_filter = ('is_staff', 'is_active', 'user_roles', 'auth_type', 'auth_status')  # Add more filters as needed
    search_fields = ('username', 'email', 'phone_number')  # Enable search on phone number as well
    ordering = ('-date_joined',)
    
    # Manually define list_display (exclude password and other fields)
    list_display = (
        'username', 'email', 'phone_number', 'user_roles', 'auth_type', 'auth_status', 'is_active', 'date_joined', 'full_name', 'last_login'
    )

    # Using custom form to exclude the password field
    form = CustomUserForm

    # Customize the fieldsets for the detail view (to remove password from form view)
    fieldsets = (
        (None, {'fields': ('username', 'email', 'phone_number', 'user_roles', 'auth_type', 'auth_status', 'photo', 'is_active')}),
        ('Permissions', {'fields': ('is_staff',)}),
        ('Important Dates', {'fields': ('date_joined', 'last_login')}),
        ('Advanced options', {'fields': ('is_superuser', 'user_permissions', 'groups')}),
    )

    # Optionally, exclude 'password' in the list filter as well
    filter_horizontal = ('user_permissions', 'groups')


@admin.register(UserConfirmation)
class UserConfirmationAdmin(ImportExportModelAdmin, BaseAdmin):
    resource_classes = [UserConfirmationResource]
    list_display = tuple(f.name for f in UserConfirmation._meta.fields if f.name)

