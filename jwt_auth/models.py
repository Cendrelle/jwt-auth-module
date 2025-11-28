from django.db import models
from django.conf import settings
from django.utils import timezone

# Create your models here.

class RefreshToken(models.Model):
    """
    Modèle pour stocker les refresh tokens actifs.
    Chaque token est lié à un utilisateur et possède un identifiant unique (jti).
    """
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    jti = models.CharField(max_length=255, unique=True)  
    token_hash = models.CharField(max_length=255)  
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    revoked = models.BooleanField(default=False)

    def is_expired(self):
        return timezone.now() >= self.expires_at

    def revoke(self):
        self.revoked = True
        self.save(update_fields=["revoked"])

    def __str__(self):
        return f"RefreshToken(user={self.user}, revoked={self.revoked})"
