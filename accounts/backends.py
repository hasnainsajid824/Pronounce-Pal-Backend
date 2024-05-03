# backend.py
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model
from .models import UserProfile

class ProfileBackend(ModelBackend):
    def authenticate(self, request, profile_name=None, password=None, **kwargs):
        try:
            # Retrieve the user based on the profile_name
            user_profile = UserProfile.objects.get(profile_name=profile_name)

            # Check if the password is correct for the associated User
            if user_profile.user.check_password(password):
                return user_profile.user  # Return the user associated with the profile

        except UserProfile.DoesNotExist:
            return None  # Return None if the profile does not exist

    def get_user(self, user_id):
        User = get_user_model()
        try:
            # Retrieve the user based on the user_id
            return User.objects.get(id=user_id)
        except User.DoesNotExist:
            return None  # Return None if the user does not exist
