from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from accounts.serializers import LoginSerializer, SendPasswordResetEmailSerializer, UserChangePasswordSerializer, UserLoginSerializer, UserPasswordResetSerializer, UserProfileSerializer, UserProfileSerializer1, UserRegistrationSerializer
from django.contrib.auth import authenticate
from accounts.renderers import UserRenderer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from rest_framework import generics, permissions
from django.shortcuts import get_object_or_404
import pandas as pd
import Levenshtein
from sklearn.preprocessing import LabelEncoder
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences
import numpy as np
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse
from .models import User, UserProfile  # Import your User model
from django.contrib.auth import get_user_model
from rest_framework.authtoken.models import Token
from rest_framework_simplejwt.tokens import AccessToken
import os

User = get_user_model()

# Ensure you're using the correct User model

# Generate Token Manually
def get_tokens_for_user(user):
  access = AccessToken.for_user(user)
  refresh= RefreshToken.for_user(user)
  

  return {
      'refresh': str(refresh),
      'access': str(access),
  }

class UserRegistrationView(APIView):
  renderer_classes = [UserRenderer]
  def post(self, request, format=None):
    serializer = UserRegistrationSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    user = serializer.save()
    token = get_tokens_for_user(user)
    return Response({'token':token, 'msg':'Registration Successful'}, status=status.HTTP_201_CREATED)

class UserLoginView(APIView):
  renderer_classes = [UserRenderer]
  def post(self, request, format=None):
    serializer = UserLoginSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    email = serializer.data.get('email')
    password = serializer.data.get('password')
    user = authenticate(email=email, password=password)
    if user is not None:
      token = get_tokens_for_user(user)
      return Response({'user_id': user.id,'token':token, 'msg':'Login Success'}, status=status.HTTP_200_OK)
    else:
      return Response({'errors':{'non_field_errors':['Email or Password is not Valid']}}, status=status.HTTP_400_BAD_REQUEST)

class UserProfileView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data)

# class UserChangePasswordView(APIView):
#   renderer_classes = [UserRenderer]
#   permission_classes = [IsAuthenticated]
#   def post(self, request, format=None):
#     serializer = UserChangePasswordSerializer(data=request.data, context={'user':request.user})
#     serializer.is_valid(raise_exception=True)
#     return Response({'msg':'Password Changed Successfully'}, status=status.HTTP_200_OK)

class SendPasswordResetEmailView(APIView):
  renderer_classes = [UserRenderer]
  def post(self, request, *args, **kwargs):
    serializer = SendPasswordResetEmailSerializer(data=request.data, context={'request': request})
    serializer.is_valid(raise_exception=True)
    return Response({'msg':'Password Reset link send. Please check your Email'}, status=status.HTTP_200_OK)

class UserPasswordResetView(APIView):
  renderer_classes = [UserRenderer]
  def post(self, request, uid, token, format=None):
    serializer = UserPasswordResetSerializer(data=request.data, context={'uid':uid, 'token':token})
    serializer.is_valid(raise_exception=True)
    return Response({'msg':'Password Reset Successfully'}, status=status.HTTP_200_OK)




#________________________________________________________________________________________________________________________
from rest_framework import generics, status
from django.contrib.auth import authenticate, login


class UserProfileListCreateView(generics.ListCreateAPIView):
    serializer_class = UserProfileSerializer1

    def get_queryset(self):
        return UserProfile.objects.filter(user=self.request.user)

    def create(self, request, *args, **kwargs):
        profile_name = request.data.get('profile_name')

        # Check if the user already has four profiles
        if self.get_queryset().count() >= 4:
            return Response({'detail': 'You can create only four profiles.'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if the profile name already exists for the user
        if self.get_queryset().filter(profile_name=profile_name).exists():
            return Response({'detail': 'Profile name already exists.'}, status=status.HTTP_400_BAD_REQUEST)

        # Set the user field to the main user before saving the profile
        request.data['user'] = request.user.id

        # Create the profile
        return super().create(request, *args, **kwargs)

class DeleteUserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, profile_id, *args, **kwargs):
        try:
            print(f"Requesting deletion for profile ID: {profile_id}")
            profile = UserProfile.objects.get(id=profile_id, user=request.user)
            profile.delete()
            print(f"Profile deleted successfully: {profile_id}")
            return Response({'detail': 'Profile deleted successfully.'}, status=status.HTTP_204_NO_CONTENT)
        except UserProfile.DoesNotExist:
            print(f"Profile not found for ID: {profile_id}")
            return Response({'detail': 'Profile not found.'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            print(f"An error occurred: {e}")
            return Response({'detail': 'An error occurred.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UserProfileDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, user_id, profile_name, format=None):
        print(f"Received request for user_id: {user_id}, profile_name: {profile_name}")
        try:
            profile = UserProfile.objects.get(user_id=user_id, profile_name=profile_name)
            print(f"Profile found: {profile}")
            return Response({'profile_id': profile.id}, status=status.HTTP_200_OK)
        except UserProfile.DoesNotExist:
            print(f"Profile not found for user_id: {user_id}, profile_name: {profile_name}")
            return Response({'detail': 'Profile not found.'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            print(f"An error occurred: {e}")
            return Response({'detail': 'An error occurred.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserProfileListAPIView(generics.ListAPIView):
    serializer_class = UserProfileSerializer1

    def get_queryset(self):
        user_id = self.kwargs['user_id']
        return UserProfile.objects.filter(user_id=user_id)
    
class LoginView(generics.CreateAPIView):
    serializer_class = LoginSerializer

    def create(self, request, *args, **kwargs):
        profile_name = request.data.get('profile_name')
        password = request.data.get('password')

        # Authenticate user using the provided profile credentials
        user = authenticate(request, profile_name=profile_name, password=password)
        print(user)

        if user:
            # If authentication is successful, generate or retrieve the token
            # token, created = Token.objects.get_or_create(user=user)
            token = get_tokens_for_user(user)


            return Response({'detail': 'Login successful','token': token}, status=status.HTTP_200_OK)
        else:
            return Response({'detail': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)


df = pd.read_csv('Words_For_Kids.csv')
df = df.dropna(subset=['Pronunciation'])

max_sequence_length = 15
urdu_char = {
    'ا': 1, 'ی': 2, 'ر': 3, 'ن': 4, 'و': 5, 'ت': 6, 'ل': 7, 'م': 8, 'ک': 9, 'س': 10,
    'ب': 11, 'ں': 12, 'ھ': 13, 'د': 14, 'ہ': 15, 'پ': 16, 'ٹ': 17, 'ج': 18, 'گ': 19,
    'چ': 20, 'ے': 21, 'ف': 22, 'ش': 23, 'ئ': 24, 'ق': 25, 'ع': 26, 'ز': 27, 'ڑ': 28,
    'ح': 29, 'خ': 30, 'ڈ': 31, 'ط': 32, 'ص': 33, 'غ': 34, 'ؤ': 35, 'ض': 36, 'آ': 37,
    'ذ': 38, 'ث': 39, 'ظ': 40, 'ء': 41, 'ژ': 42, 'ۃ': 43
}

pronounce_char = {
      1: ' ', 2: '_', 3: 'a', 4: 'i', 5: 'd', 6: 'n', 7: 't', 8: 'r', 9: 's',
      10: 'h', 11: 'u', 12: 'o', 13: 'm', 14: 'l', 15: 'z', 16: 'k', 17: 'y',
      18: 'b', 19: 'g', 20: 'j', 21: 'p', 22: 'v', 23: 'f', 24: 'q', 25: 'e',
      26: 'x'
}

train_df, _ = train_test_split(df, test_size=0.2, random_state=42)

pronunciation_encoder = LabelEncoder()
train_df['Encoded_Pronunciation'] = pronunciation_encoder.fit_transform(train_df['Pronunciation'])

model = load_model('Pronunounce_model(2).h5')

def find_closest_word(input_pronunciation, train_df, pronunciation_encoder):
    try:
        input_encoded = pronunciation_encoder.transform([input_pronunciation])[0]
    except ValueError:
        df['Levenshtein_Distance'] = df['Pronunciation'].apply(lambda x: Levenshtein.distance(input_pronunciation, x))
    
        # Find the word with the closest pronunciation in the entire dataset
        closest_word_index = df['Levenshtein_Distance'].idxmin()
        closest_word = df.loc[closest_word_index, 'Words']
        return closest_word
    train_df['Levenshtein_Distance'] = train_df['Encoded_Pronunciation'].apply(lambda x: Levenshtein.distance(str(input_encoded), str(x)))
    closest_word_index = train_df['Levenshtein_Distance'].idxmin()
    closest_word = train_df.loc[closest_word_index, 'Words']
    return closest_word


# from metaphone import doublemetaphone

# def encode_pronunciation(pronunciation):
#     primary, secondary = doublemetaphone(pronunciation)
#     return primary or secondary

# def find_closest_word(input_pronunciation, train_df, pronunciation_encoder):
#     try:
#         input_encoded = pronunciation_encoder.transform([input_pronunciation])[0]
#     except ValueError:
#         # Encode input pronunciation using Double Metaphone if encoder fails
#         input_encoded = encode_pronunciation(input_pronunciation)
        
#         # Compute Levenshtein distance for the entire dataset
#         train_df['Levenshtein_Distance'] = train_df['Pronunciation'].apply(
#             lambda x: levenshtein_distance(input_pronunciation, x)
#         )
#     else:
#         # Compute Levenshtein distance for the encoded dataset
#         train_df['Levenshtein_Distance'] = train_df['Encoded_Pronunciation'].apply(
#             lambda x: levenshtein_distance(str(input_encoded), str(x))
#         )
        
#     # Find the word with the closest pronunciation
#     closest_word_index = train_df['Levenshtein_Distance'].idxmin()
#     closest_word = train_df.loc[closest_word_index, 'Words']
#     return closest_word

def urdu_tokenizer(text, char_to_index):
    tokens = []
    for char in text:
        if char in char_to_index:
            tokens.append(char_to_index[char])
        else:
            pass
    return [tokens]

def pro_tokenizer(indices, index_to_char):
    return ''.join(index_to_char[index] for index in indices if index in index_to_char)

def predict_pronunciation(new_urdu_word):
    tokenized_word = urdu_tokenizer(new_urdu_word, urdu_char)
    padded_word = pad_sequences(tokenized_word, maxlen=max_sequence_length, padding='post')
    predictions = model.predict(padded_word)
    predicted_pronunciation_indices = [np.argmax(pred) for pred in predictions[0]]
    predict_pronunciation = pro_tokenizer(predicted_pronunciation_indices, pronounce_char)
    return predict_pronunciation.upper()

@csrf_exempt
def process_text(request):
    if request.method == 'POST':
        data = request.POST.get('data')
        print(data)
        if not data:
            return JsonResponse({'error': 'No data provided'}, status=400)

        input_words = data.split()
        predicted_pronunciations = []
        for word in input_words:
            predicted_pronunciation = predict_pronunciation(word)
            predicted_pronunciations.append(predicted_pronunciation)

        combined_pronunciation = ' '.join(predicted_pronunciations)
        closest_word = find_closest_word(combined_pronunciation, train_df, pronunciation_encoder)

        if closest_word:
            return JsonResponse({'closest_word': closest_word}, status=200)
        else:
            return JsonResponse({'error': 'No closest word found'}, status=404)
    else:
        return HttpResponse("Method not allowed", status=405)
