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

class UserChangePasswordSerializer(serializers.Serializer):
  password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
  password2 = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
  class Meta:
    fields = ['password', 'password2']

  def validate(self, attrs):
    password = attrs.get('password')
    password2 = attrs.get('password2')
    user = self.context.get('user')
    if password != password2:
      raise serializers.ValidationError("Password and Confirm Password doesn't match")
    user.set_password(password)
    user.save()
    return attrs

class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        fields = ['email']

    def validate(self, attrs):
        email = attrs.get('email')
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            
            # Get the current request's scheme (http or https) and host (domain)
            # request = self.context.get('request')
            # scheme = request.scheme if request else 'http'
            # host = request.get_host() if request else 'localhost'
            server_link = os.environ.get('LINK')
            # link = f'{scheme}://{host}{reverse("reset-password", args=[uid, token])}'
            link = f'{server_link}{reverse("reset-password", args=[uid, token])}'

            subject = os.environ.get('RESET_EMAIL_SUBJECT')
            reset_password_email = os.environ.get('RESET_EMAIL_BODY')
            body = reset_password_email + link
            print(body)
            data = {
                'subject': subject,
                'body': body,
                'to_email': user.email
            }
            Util.send_email(data)
            return attrs
        else:
            raise serializers.ValidationError('You are not a Registered User')

class UserPasswordResetSerializer(serializers.Serializer):
  password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
  password2 = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
  class Meta:
    fields = ['password', 'password2']

  def validate(self, attrs):
    try:
      password = attrs.get('password')
      password2 = attrs.get('password2')
      uid = self.context.get('uid')
      token = self.context.get('token')
      if password != password2:
        raise serializers.ValidationError("Password and Confirm Password doesn't match")
      id = smart_str(urlsafe_base64_decode(uid))
      user = User.objects.get(id=id)
      if not PasswordResetTokenGenerator().check_token(user, token):
        raise serializers.ValidationError('Token is not Valid or Expired')
      user.set_password(password)
      user.save()
      return attrs
    except DjangoUnicodeDecodeError as identifier:
      PasswordResetTokenGenerator().check_token(user, token)
      raise serializers.ValidationError('Token is not Valid or Expired')
  


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