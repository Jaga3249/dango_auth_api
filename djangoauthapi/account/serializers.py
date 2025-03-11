from rest_framework import serializers
from account.models import User
from django.utils.encoding import smart_str,force_bytes,DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator

class UserRegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(
        style={'input_type': 'password'}, write_only=True
    )
    email = serializers.EmailField()

    class Meta:
        model = User
        fields = ["email", "name", "password", "password2", "tc"]
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def validate(self, attrs):
        password = attrs.get("password")
        password2 = attrs.get("password2")
        email = attrs.get("email")

        # Check if passwords match
        if password != password2:
            raise serializers.ValidationError({"password": "Password and Confirm Password do not match."})

        # Ensure email is not empty or incorrectly formatted
        if not email or "@" not in email:
            raise serializers.ValidationError({"email": "Invalid email format."})

        return attrs
    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return value
    def create(self, validated_data):
        """Custom create method to handle password hashing"""
        validated_data.pop("password2")  # Remove password2 as it's not needed in DB
        user = User.objects.create_user(**validated_data)  # Ensure password is hashed
        return user

    def to_representation(self, instance):
        """Override the representation to return single-string error messages"""
        response = super().to_representation(instance)
        errors = {}

        for field, value in response.items():
            if isinstance(value, list) and len(value) == 1:
                errors[field] = value[0]  # Convert list to string if only one error
            else:
                errors[field] = value  # Keep as is

        return errors

class UserLoginSerializers(serializers.ModelSerializer):
    email=serializers.EmailField(max_length=255.)
    class Meta:
        model=User
        fields=["email","password"]
class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model=User
        fields=["email","id","name"]
class UserPassowrdChangeSerializer(serializers.ModelSerializer):
    password=serializers.CharField(max_length=255,style={
        'input_type':'password'
    },write_only=True)
    password2=serializers.CharField(max_length=255,style={
        'input_type':'password'
    },write_only=True)
    class Meta:
        model=User
        fields=['password','password2']
    
    def validate(self, attrs):
        password=attrs.get('password')
        password2=attrs.get('password2')
        user=self.context.get('user')
        if password != password2:
            raise serializers.ValidationError({"password": "Password and Confirm Password do not match."})
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
      user = User.objects.get(email = email)
      uid = urlsafe_base64_encode(force_bytes(user.id))
      print('Encoded UID', uid)
      token = PasswordResetTokenGenerator().make_token(user)
      print('Password Reset Token', token)
      link = 'http://localhost:3000/api/user/reset/'+uid+'/'+token
      print('Password Reset Link', link)
      # Send EMail
      body = 'Click Following Link to Reset Your Password '+link
      data = {
        'subject':'Reset Your Password',
        'body':body,
        'to_email':user.email
      }
      # Util.send_email(data)
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
  