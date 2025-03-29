from django.db import models
from django.contrib.auth.models import User
from django.core.validators import FileExtensionValidator
from django.core.exceptions import ValidationError
import uuid
from django.utils import timezone
import datetime

def validate_image_size(value):
    """
    Validate that uploaded images don't exceed 5MB in size
    
    Args:
        value: The uploaded file object
        
    Raises:
        ValidationError: If file exceeds size limit
    """
    filesize = value.size
    if filesize > 5 * 1024 * 1024:  # 5MB
        raise ValidationError("Maximum file size is 5MB")

class UserProfile(models.Model):
    """
    Extended user profile information beyond Django's built-in User model
    
    This model contains additional user information that isn't part of the
    default Django User model. It has a one-to-one relationship with User.
    
    Attributes:
        user: OneToOne link to the related Django User instance
        profile_picture: Optional user profile image (JPG/PNG, max 5MB)
        postcode: User's postal code for location-based features
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    profile_picture = models.ImageField(
        upload_to='profile_pictures/',
        null=True,
        blank=True,
        validators=[
            FileExtensionValidator(allowed_extensions=['jpg', 'jpeg', 'png']),
            validate_image_size
        ]
    )
    postcode = models.CharField(max_length=20, blank=True, null=True)

    def __str__(self):
        return f"{self.user.username}'s profile"

class PasswordResetToken(models.Model):
    """
    Stores tokens for password reset functionality
    
    This model manages the lifecycle of password reset tokens including:
    - Token creation with UUID for security
    - Expiration tracking (default 24 hours)
    - Usage status to prevent token reuse
    
    Attributes:
        user: The user requesting password reset
        token: Unique UUID for secure token verification
        created_at: When the token was created
        expires_at: When the token expires (24 hours after creation)
        used: Whether the token has already been used
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='password_reset_tokens')
    token = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)

    def save(self, *args, **kwargs):
        if not self.expires_at:
            # Token expires after 24 hours
            self.expires_at = timezone.now() + datetime.timedelta(hours=24)
        super().save(*args, **kwargs)

    def is_valid(self):
        """
        Check if token is still valid (not used and not expired)
        
        Returns:
            bool: True if token is valid, False otherwise
        """
        return not self.used and self.expires_at > timezone.now()

    def __str__(self):
        return f"Password reset token for {self.user.username}"