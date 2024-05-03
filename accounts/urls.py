from django.urls import path,include
from accounts.views import SendPasswordResetEmailView, UserLoginView, UserProfileView, UserRegistrationView, UserPasswordResetView
from .views import LoginView, UserProfileListAPIView, UserProfileListCreateView, process_text


urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('profile/', UserProfileView.as_view(), name='profile'),
    # path('changepassword/', UserChangePasswordView.as_view(), name='changepassword'),
    path('send-reset-password-email/', SendPasswordResetEmailView.as_view(), name='send-reset-password-email'),
    path('reset-password/<uid>/<token>/', UserPasswordResetView.as_view(), name='reset-password'),
    path('create_profiles/', UserProfileListCreateView.as_view(), name='profile-list'),
    path('list_profiles/<int:user_id>/', UserProfileListAPIView.as_view(), name='user-profile-list'),
    path('login/profile', LoginView.as_view(), name='login'),
    path('process_text/', process_text, name='process_text'),



]