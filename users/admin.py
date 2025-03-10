from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils.translation import gettext_lazy as _
from .models import ArraivUser

class ArraivUserAdmin(UserAdmin):
    ordering = ['email']
    list_display = ['email', 'first_name', 'is_staff', 'is_active','date_joined']
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        (_('Personal Info'), {'fields': ('first_name',)}),
        (_('Permissions'), {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        (_('Important Dates'), {'fields': ('last_login',)}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'first_name', 'password1', 'password2'),
        }),
    )
    search_fields = ['email', 'first_name']
    filter_horizontal = ('groups', 'user_permissions')

admin.site.register(ArraivUser, ArraivUserAdmin)
