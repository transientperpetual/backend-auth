from rest_framework import serializers
from .models import ArraivUser
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer


class ArraivUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = ArraivUser
        fields = ['first_name', 'email', 'password']
        extra_kwargs = {"password": {"write_only": True}}

    def create(self, validated_data):
        user = ArraivUser.objects.create_user(**validated_data) 
        return user

#by default, the TokenObtainPairSerializer uses the username field to authenticate the user.
#Hence we need to override the validate method to use the email field instead.
class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        email = attrs.get("email")
        password = attrs.get("password")

        if not email or not password:
            raise serializers.ValidationError("Email & password required, or login with Google")

        try:
            user = ArraivUser.objects.get(email=email)
        except ArraivUser.DoesNotExist:
            raise serializers.ValidationError("Email not registered.")

        if not user.is_active:
            raise serializers.ValidationError("User account is inactive.")
    
        if not user.is_email_verified:  # Restrict login for unverified users
            raise serializers.ValidationError("Email not verified")

        if not user.check_password(password):
            raise serializers.ValidationError("Incorrect password.")

        attrs["username"] = user.email 
        return super().validate(attrs)