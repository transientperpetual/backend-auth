from rest_framework_simplejwt.authentication import JWTAuthentication

class CookieJWTAuthentication(JWTAuthentication):
    def authenticate(self, request):
        from django.conf import settings
        
        # Use the cookie name from settings
        cookie_name = settings.SIMPLE_JWT.get('AUTH_COOKIE', 'access_token')
        access_token = request.COOKIES.get(cookie_name)
        
        if access_token:
            validated_token = self.get_validated_token(access_token)
            return self.get_user(validated_token), validated_token
        
        # Fallback to header-based authentication
        # return super().authenticate(request)
        return None
