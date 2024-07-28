from django.urls import path,include
from accounts.views import DeleteUserProfileView, UserProfileDetailView,  UserLoginView, UserProfileView, UserRegistrationView
from .views import LoginView, UserProfileListAPIView, UserProfileListCreateView, process_text, GetChildProgressView, PasswordResetView, PasswordResetConfirmView, UserProfileEditView


urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('profile/', UserProfileView.as_view(), name='profile'),
    path('create_profiles/', UserProfileListCreateView.as_view(), name='profile-list'),
    path('list_profiles/<int:user_id>/', UserProfileListAPIView.as_view(), name='user-profile-list'),
    path('login/profile', LoginView.as_view(), name='login'),
    path('profile/edit/<int:profile_id>/', UserProfileEditView.as_view(), name='profile-edit'),
    path('delete_profile/<int:profile_id>/', DeleteUserProfileView.as_view(), name='delete-profile'),
    path('profile_id/<int:user_id>/<str:profile_name>/', UserProfileDetailView.as_view(), name='profile-detail'),
    path('profile-progress/<int:profile_id>/', GetChildProgressView.as_view(), name='profile_progress'),  
    path('send-reset-otp/', PasswordResetView.as_view(), name='send-reset-otp'),
    path('reset-password/', PasswordResetConfirmView.as_view(), name='reset-password'),
    path('process_text/', process_text, name='process_text'),
]