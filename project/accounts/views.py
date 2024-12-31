from django.shortcuts import render

# Create your views here.
from django.contrib.auth import authenticate, login
from django.shortcuts import render, redirect
from django.contrib import messages

def login_view(request):
    if request.method == 'POST':
        username_or_email = request.POST['username_or_email']
        password = request.POST['password']

        user = authenticate(request, username=username_or_email, password=password)
        if user:
            login(request, user)
            return redirect('dashboard')
        else:
            messages.error(request, 'Invalid credentials')
    return render(request, 'accounts/login.html')

from django.contrib.auth.models import User

def signup_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']

        if password == confirm_password:
            User.objects.create_user(username=username, email=email, password=password)
            return redirect('login')
        else:
            messages.error(request, 'Passwords do not match')
    return render(request, 'accounts/signup.html')

from django.contrib.auth.forms import PasswordResetForm

def forgot_password_view(request):
    if request.method == 'POST':
        email = request.POST['email']
        form = PasswordResetForm({'email': email})
        if form.is_valid():
            form.save(request=request)
            messages.success(request, 'Reset instructions sent')
            return redirect('login')
    return render(request, 'accounts/forgot_password.html')

from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm

@login_required
def change_password_view(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Password changed successfully')
            return redirect('dashboard')
    else:
        form = PasswordChangeForm(request.user)
    return render(request, 'accounts/change_password.html', {'form': form})

@login_required
def dashboard_view(request):
    return render(request, 'accounts/dashboard.html', {'username': request.user.username})

@login_required
def profile_view(request):
    return render(request, 'accounts/profile.html', {
        'user': request.user
    })

from django.contrib.auth import logout

def logout_view(request):
    logout(request)
    return redirect('login')
