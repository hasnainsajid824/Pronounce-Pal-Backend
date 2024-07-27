from rest_framework import serializers
from accounts.models import User, UserProfile
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from accounts.utils import Util
from django.urls import reverse
import os


class UserRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'password']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)


class UserLoginSerializer(serializers.ModelSerializer):
  email = serializers.EmailField(max_length=255)
  class Meta:
    model = User
    fields = ['email', 'password']

class UserProfileSerializer(serializers.ModelSerializer):
  class Meta:
    model = User
    fields = ['id', 'email', 'first_name','last_name']





class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()

class PasswordResetConfirmSerializer(serializers.Serializer):
    otp = serializers.CharField()
    new_password = serializers.CharField()
    confirm_password = serializers.CharField()
    # def validate(self, data):
    #     if data['new_password'] != data['confirm_password']:
    #         raise serializers.ValidationError("Passwords do not match.")
    #     return data

class UserProfileSerializer1(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ['profile_name', 'password', 'user','age', 'total_words_attempted', 'correctly_pronounced_words','progress']
        extra_kwargs = {'password': {'write_only': True}}
    
    # def create(self, validated_data):
    #     user = self.context['request'].user  # Get the authenticated user from the context
    #     profile = UserProfile.objects.create(user=user, **validated_data)
    #     return profile
        
class LoginSerializer(serializers.Serializer):
    profile_name = serializers.CharField()
    password = serializers.CharField(write_only=True)