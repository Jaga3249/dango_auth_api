from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from account.serializers import UserRegistrationSerializer,UserLoginSerializers,UserProfileSerializer,UserPassowrdChangeSerializer,SendPasswordResetEmailSerializer,UserPasswordResetSerializer
from django.contrib.auth import authenticate
from account.renderers import UserRenderers
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import AllowAny,IsAuthenticated


# Create your views here.
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }
class UserRegiStationView(APIView):
    def post(self,request,format=None):
      renderer_classes=[UserRenderers]
      serializer=UserRegistrationSerializer(data=request.data)
      if serializer.is_valid():
         user=serializer.save()
         token=get_tokens_for_user(user)
         return Response({'msg':'user register sucessful','token':token},status=status.HTTP_200_OK)
      
      return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
    
# class UserLoginView(APIView):
#    def post(self,request,format=None):
      # renderer_classes=[UserRenderers]
#       seriallizers=UserLoginSerializers(data=request.data)
#       if seriallizers.is_valid(raise_exception=True):
#          email=seriallizers.data.get("email")
#          password=seriallizers.data.get("password")
#          user=authenticate(email=email,password=password)
#          token=get_tokens_for_user(user)
#          if user is not None:
#             return Response({'msg':'Login sucess','token':token},status=status.HTTP_200_OK)
#          else:
#             return Response({'error':{'non_field_errors':['email and password is not valid']}},status=status.HTTP_404_NOT_FOUND)
#       return Response(seriallizers.errors,status=status.HTTP_400_BAD_REQUEST)

class UserLoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, format=None):
        serializer = UserLoginSerializers(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email = serializer.validated_data.get("email")  # Use `validated_data`
            password = serializer.validated_data.get("password")

            # Authenticate the user
            user = authenticate(request, email=email, password=password)
            
            if user is not None:
                token = get_tokens_for_user(user)
                return Response({'msg': 'Login successful', 'token': token}, status=status.HTTP_200_OK)
            else:
                return Response({'error': {'non_field_errors': ['Invalid email or password']}}, status=status.HTTP_401_UNAUTHORIZED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]  # Correctly placed as a class attribute
    renderer_classes = [UserRenderers]  # Correctly placed as a class attribute

    def get(self, request, format=None):
      #   print("user",request.user,request.data)  # Debugging

        user = request.user  # Get the authenticated user
        if not user.is_authenticated:  # Check if user is authenticated
            return Response({'error': 'Authentication required'}, status=status.HTTP_401_UNAUTHORIZED)

        serializer = UserProfileSerializer(user)  # Serialize user instance
        print("serializer",serializer.data)
        return Response(serializer.data, status=status.HTTP_200_OK)

class UserChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]  # Correctly placed as a class attribute
    renderer_classes = [UserRenderers]  # Correctly placed as a class attribute
    def post(self,request,format=None):
      serializer=UserPassowrdChangeSerializer(data=request.data,context={'user':request.user})
      if serializer.is_valid(raise_exception=True):
          return Response({'msg':'password changed sucessfully'},status=status.HTTP_200_OK)
      return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)

class SendPasswordResetEmailView(APIView):
    
    def post(self,request,format=None):
        serializer=SendPasswordResetEmailSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
          return Response({'msg':'Reset password link send to your email'},status=status.HTTP_200_OK)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
class UserResetPasswordView(APIView):
    renderer_classes = [UserRenderers] 
    def post(self,request,uid,token,format=None):
        serializer=UserPasswordResetSerializer(data=request.data,context={'token':token,'uid':uid})
        if serializer.is_valid(raise_exception=True):
          return Response({'msg':'Password reset sucessfully'},status=status.HTTP_200_OK)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)

       
      