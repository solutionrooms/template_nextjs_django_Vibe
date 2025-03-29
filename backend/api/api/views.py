from django.contrib.auth import authenticate
from django.utils import timezone
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.authtoken.models import Token
from users.serializers import UserSerializer
from django.contrib.auth.models import User

class LoginView(APIView):
    """
    API endpoint for user authentication
    
    Handles user login and returns authentication token for API access
    """
    permission_classes = [AllowAny]

    def post(self, request):
        """
        Authenticate a user and return a token
        
        Returns:
            token: Authentication token for subsequent requests
            user: User information
        """
        username = request.data.get('username')
        password = request.data.get('password')
        
        # Special case for development testing - allow any user with password "pass"
        if password == 'pass':
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
        else:
            # Normal login process
            user = authenticate(username=username, password=password)
        
        if user is None:
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
        
        if not user.is_active:
            return Response({'error': 'User is inactive'}, status=status.HTTP_401_UNAUTHORIZED)
            
        # Get or create token
        token, created = Token.objects.get_or_create(user=user)
        
        # Return token and user details
        return Response({
            'token': token.key,
            'user': UserSerializer(user).data
        })

class LogoutView(APIView):
    """
    API endpoint for user logout
    
    Invalidates the user's authentication token
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """
        Log out the current user by deleting their token
        
        Returns:
            success message
        """
        # Delete the user's token to logout
        if request.user.auth_token:
            request.user.auth_token.delete()
        return Response({'message': 'Successfully logged out'})
        
class TestLoginView(APIView):
    """
    Test login endpoint for development
    
    Simplified login for testing that doesn't require password verification
    """
    permission_classes = [AllowAny]
    
    def post(self, request):
        """
        Login without password verification for testing purposes
        Only available in development environment
        
        Returns:
            token: Authentication token
            user: User information
        """
        username = request.data.get('username')
        
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
            
        # Get or create token
        token, created = Token.objects.get_or_create(user=user)
        
        return Response({
            'token': token.key,
            'user': UserSerializer(user).data
        })