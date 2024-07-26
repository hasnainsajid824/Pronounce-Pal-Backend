from django.urls import path,include
from accounts.views import DeleteUserProfileView, UserProfileDetailView, SendPasswordResetEmailView, UserLoginView, UserProfileView, UserRegistrationView, UserPasswordResetView
from .views import LoginView, UserProfileListAPIView, UserProfileListCreateView, process_text, GetChildProgressView, SendOTPView, VerifyOTPView, ResetPasswordView

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
    path('delete_profile/<int:profile_id>/', DeleteUserProfileView.as_view(), name='delete-profile'),
    path('profile_id/<int:user_id>/<str:profile_name>/', UserProfileDetailView.as_view(), name='profile-detail'),
    path('profile-progress/<int:profile_id>/', GetChildProgressView.as_view(), name='profile_progress'),  
    path('send-otp/', SendOTPView.as_view(), name='send-otp'),
    path('verify-otp/', VerifyOTPView.as_view(), name='verify-otp'),
    path('reset-password/', ResetPasswordView.as_view(), name='reset-password'),
]