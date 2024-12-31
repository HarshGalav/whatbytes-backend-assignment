from django.shortcuts import render

# Create your views here.
from django.contrib.auth import authenticate, login,logout,update_session_auth_hash
from django.shortcuts import render, redirect
from django.contrib import messages
from django.core.mail import EmailMessage
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm,PasswordResetForm
from django.contrib.auth.models import User

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
    return render(request, 'login.html')



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
    return render(request, 'signup.html')


def forgot_password_view(request):
    if request.method == 'POST':
        email = request.POST['email']
        form = PasswordResetForm({'email': email})
        if form.is_valid():
            form.save(request=request)

            email_message = EmailMessage(
                'Password Reset Instructions',  
                'You requested to reset your password. Please check your inbox for further instructions.',  
                to=[email]  
            )
            email_message.send()

            messages.success(request, 'Reset instructions sent to your email.')
            return redirect('login')
        else:
            messages.error(request, 'Invalid email address. Please try again.')
    return render(request, 'forgot_password.html')


@login_required
def change_password_view(request):
    # print("REQ:", request)
    if request.method == 'POST':
        form = PasswordChangeForm(user=request.user,data= request.POST)
        print("Form:", form.is_valid())
        if form.is_valid():
            print("VALID")
            form.save()
            update_session_auth_hash(request,form.user)
            messages.success(request, 'Password changed successfully')
            return redirect('dashboard')
        else:
            print("Invalid", form.errors)
    else:
        form = PasswordChangeForm(user=request.user)
    # return None
    return render(request, 'change_password.html', {'form': form})

@login_required
def dashboard_view(request):
    return render(request, 'dashboard.html', {'username': request.user.username})

@login_required
def profile_view(request):
    return render(request, 'profile.html', {
        'user': request.user
    })


def logout_view(request):
    logout(request)
    return redirect('login')
