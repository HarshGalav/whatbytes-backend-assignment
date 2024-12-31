from django.urls import path
from . import views
from django.contrib.auth import views as auth_views



urlpatterns = [
    
    path('login/', views.login_view, name='login'),
    path('signup/', views.signup_view, name='signup'),
    path('forgot-password/', views.forgot_password_view, name='forgot_password'),
    path('change-password/', views.change_password_view, name='change_password'),
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('profile/', views.profile_view, name='profile'),
    path('logout/', views.logout_view, name='logout'),
    path('accounts/password_reset/', auth_views.PasswordResetView.as_view(template_name='forgot_password.html'), name='password_reset'),
    path('accounts/password_reset/done/', auth_views.PasswordResetDoneView.as_view(template_name='password_reset_done.html'), name='password_reset_done'),
    path('accounts/reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(template_name='password_reset_complete.html'), name='password_reset_confirm'),
    path('accounts/reset/done/', auth_views.PasswordResetCompleteView.as_view(template_name='password_reset_complete.html'), name='password_reset_complete'),

    
]
