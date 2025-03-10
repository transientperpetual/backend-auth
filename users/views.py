from django.shortcuts import render
from .models import ArraivUser
from .serializers import ArraivUserSerializer
from rest_framework.generics import ListAPIView, RetrieveUpdateDestroyAPIView, CreateAPIView
from rest_framework.views import APIView
from django.utils.timezone import now
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAdminUser
from rest_framework_simplejwt.views import TokenObtainPairView
from .serializers import CustomTokenObtainPairSerializer
from django.core.mail import send_mail
from rest_framework.response import Response
from django.conf import settings
from django.http import JsonResponse
from django.contrib.auth import get_user_model, logout
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.urls import reverse_lazy
from django.contrib import messages
from django.views.decorators.csrf import csrf_exempt

User = get_user_model()

@csrf_exempt
def delete_user_view(request):
    if request.method == 'POST':
        # User confirmed deletion
        user = request.user
        user.delete()
        logout(request)
        messages.success(request, "Your account has been deleted successfully.")
        return redirect(reverse_lazy('home'))  # Redirect to the homepage or any other page
    return render(request, 'users/delete_account_confirm.html')


class RegisterUserView(CreateAPIView):
    queryset = ArraivUser.objects.all()
    serializer_class = ArraivUserSerializer
    permission_classes = [AllowAny]

    def perform_create(self, serializer):
        user = serializer.save()
        user.is_email_verified = False  
        user.generate_otp()  # Generate OTP

        # Send OTP via email
        send_mail(
            subject="Welcome to ARRAlV!",
            message=f"Here's your OTP {user.otp}. It expires in 10 minutes.",
            from_email=settings.EMAIL_HOST_USER,
            recipient_list=[user.email],
            fail_silently=False,
        )

        return Response({"message": "User registered. Check your email for the OTP."})
    

class VerifyOTPView(APIView):
    def post(self, request):
        email = request.data.get("email")
        otp = request.data.get("otp")

        if not email or not otp:
            return JsonResponse({"error": "Email and OTP required"}, status=400)

        try:
            user = ArraivUser.objects.get(email=email)
        except ArraivUser.DoesNotExist:
            return JsonResponse({"error": "User not found"}, status=400)

        # Check OTP expiration (valid for 10 minutes)
        if user.otp != otp or (now() - user.otp_created_at).total_seconds() > 600:
            return JsonResponse({"error": "Invalid or expired OTP"}, status=400)

        # Mark email as verified
        user.is_email_verified = True
        user.otp = None  # Clear OTP after successful verification
        user.otp_created_at = None
        user.save()

        return JsonResponse({"message": "Email successfully verified!"})


class ResendOTPView(APIView):
    def post(self, request):
        email = request.data.get("email")

        if not email:
            return JsonResponse({"error": "Email required"}, status=400)

        try:
            user = ArraivUser.objects.get(email=email)
        except ArraivUser.DoesNotExist:
            return JsonResponse({"error": "User not found"}, status=400)

        if user.is_email_verified:
            return JsonResponse({"message": "Email is already verified."})

        user.generate_otp()

        # Send OTP via email
        send_mail(
            subject="Your OTP for Email Verification",
            message=f"Your new OTP is {user.otp}. It will expire in 10 minutes.",
            from_email=settings.EMAIL_HOST_USER,
            recipient_list=[user.email],
            fail_silently=False,
        )

        return JsonResponse({"message": "A new OTP has been sent to your email."})
    

class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer
    permission_classes = [AllowAny]

class ArraivUserList(ListAPIView):
    queryset = ArraivUser.objects.all()
    serializer_class = ArraivUserSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

class ArraivUserRetrieveUpdateDestroy(RetrieveUpdateDestroyAPIView):
    queryset = ArraivUser.objects.all()
    serializer_class = ArraivUserSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]


