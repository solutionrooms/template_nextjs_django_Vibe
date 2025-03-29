from django.contrib.auth.models import User
from rest_framework import serializers
from .models import UserProfile

class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for the User model with additional profile fields
    
    Includes:
    - All basic user fields
    - Display name (formatted full name with username)
    - Profile picture URL 
    - Postcode from UserProfile
    """
    display_name = serializers.SerializerMethodField()
    search_name = serializers.SerializerMethodField()
    password = serializers.CharField(write_only=True, required=False)
    profile_picture = serializers.SerializerMethodField()
    postcode = serializers.CharField(required=False, allow_blank=True, allow_null=True)

    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'is_active', 'is_staff', 
            'password', 'first_name', 'last_name', 'display_name', 
            'search_name', 'profile_picture', 'postcode'
        ]
        extra_kwargs = {
            'password': {'write_only': True},
            'username': {'required': True},
            'email': {'required': True}
        }

    def get_display_name(self, obj):
        """Generate a user-friendly display name"""
        if obj.first_name or obj.last_name:
            return f"{obj.first_name} {obj.last_name} ({obj.username})"
        return obj.username

    def get_search_name(self, obj):
        """Generate a searchable name"""
        return f"{obj.first_name} {obj.last_name} {obj.username}".lower()

    def get_profile_picture(self, obj):
        """Get profile picture URL from user profile if available"""
        try:
            profile = obj.profile
            if profile.profile_picture:
                return profile.profile_picture.url
            return None
        except UserProfile.DoesNotExist:
            return None
        
    def to_representation(self, instance):
        """Add profile fields to the representation"""
        ret = super().to_representation(instance)
        # Add postcode from profile if it exists
        try:
            profile = instance.profile
            ret['postcode'] = profile.postcode
        except UserProfile.DoesNotExist:
            ret['postcode'] = None
        return ret

    def create(self, validated_data):
        """Create a new user with related profile"""
        password = validated_data.pop('password', None)
        postcode = validated_data.pop('postcode', None)
        
        user = User.objects.create(**validated_data)
        if password:
            user.set_password(password)
            user.save()
            
        # Create or update user profile with postcode
        profile, created = UserProfile.objects.get_or_create(user=user)
        if postcode:
            profile.postcode = postcode
            profile.save()
            
        return user
        
    def update(self, instance, validated_data):
        """Update a user and related profile"""
        password = validated_data.pop('password', None)
        postcode = validated_data.pop('postcode', None)
        
        # Update user fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
            
        if password:
            instance.set_password(password)
        
        instance.save()
        
        # Update profile with postcode if provided
        if postcode is not None:
            profile, created = UserProfile.objects.get_or_create(user=instance)
            profile.postcode = postcode
            profile.save()
            
        return instance