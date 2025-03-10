from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect
from django.http import HttpResponseForbidden

User = get_user_model()

def delete_user(request, username):
    if request.user.username == username or request.user.is_superuser:
        try:
            user = User.objects.get(username=username)
            user.delete()
            return redirect('home')  # Redirect to a success page
        except User.DoesNotExist:
            return HttpResponseForbidden("User does not exist.")
    else:
        return HttpResponseForbidden("You do not have permission to delete this user.")
