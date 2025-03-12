from django.contrib import admin
from django.urls import path, include
from users import views
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView, TokenVerifyView
from users.views import CustomTokenObtainPairView, CustomTokenRefreshView


urlpatterns = [
    path('admin/', admin.site.urls),
    path('register/', views.RegisterUserView.as_view(), name='register'),
    path('verify-otp/', views.VerifyOTPView.as_view(), name='verify-otp'),
    path('resend-otp/', views.ResendOTPView.as_view(), name='resend-otp'),
    path('login/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('user/', views.ArraivUserList.as_view()),
    path('user/<int:pk>', views.ArraivUserRetrieveUpdateDestroy.as_view()),
    path('refreshtoken/', CustomTokenRefreshView.as_view(), name='token_refresh'),
    path('verifytoken/', TokenVerifyView.as_view(), name='token_verify'),
    path('deleteuser/', views.delete_user_view, name='delete_user'),
    
    path('google/login/', views.google_login, name='google_login'),
    # this is not browsable, do something to take it away from the user.
    path('google/callback/', views.google_callback, name='google_callback'),
    
    path("api/logout/", views.LogoutView.as_view(), name="logout"),
]
