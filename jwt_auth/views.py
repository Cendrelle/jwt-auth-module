
from django.contrib.auth import authenticate
from .tokens import make_access_token, make_refresh_token, hash_token, decode_jwt
from .models import RefreshToken
from django.utils import timezone
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import *
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from django.db import transaction
from django.contrib.auth.models import User

class LoginView(APIView):
    @swagger_auto_schema(
        operation_summary="Connexion d’un utilisateur",
        operation_description="Retourne un access token et un refresh token.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'username': openapi.Schema(type=openapi.TYPE_STRING, example="user@mail.com"),
                'password': openapi.Schema(type=openapi.TYPE_STRING, example="••••••••"),
            },
            required=['email', 'password'],
        ),
        responses={
            200: openapi.Response(
                description="Connexion réussie",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'access': openapi.Schema(type=openapi.TYPE_STRING),
                        'refresh': openapi.Schema(type=openapi.TYPE_STRING),
                    }
                )
            ),
            400: "Identifiants invalides"
        }
    )
    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")
        user = authenticate(request, username=username, password=password)

        if not user:
            return Response({"detail": "Identifiants invalides"}, status=status.HTTP_401_UNAUTHORIZED)

        # Générer les tokens
        access = make_access_token(user.id)
        refresh = make_refresh_token(user.id)

        # Stocker le hash du refresh token en base
        token_hash = hash_token(refresh)
        decoded_refresh = decode_jwt(refresh)
        expires_at = timezone.datetime.fromtimestamp(decoded_refresh['exp'], tz=timezone.utc)
        
        RefreshToken.objects.create(
            user=user,
            jti=decoded_refresh['jti'],
            token_hash=token_hash,
            expires_at=expires_at
        )

        return Response({
            "access": access,
            "refresh": refresh
        })

class RegisterView(APIView):
    @swagger_auto_schema(
        operation_summary="Enregistrement d’un nouvel utilisateur",
        operation_description="Permet de créer un nouvel utilisateur en fournissant un nom d'utilisateur, un email et un mot de passe.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'username': openapi.Schema(type=openapi.TYPE_STRING, example="newuser"),
                'email': openapi.Schema(type=openapi.TYPE_STRING, example="newuser@mail.com"),
                'password': openapi.Schema(type=openapi.TYPE_STRING, example="••••••••"),
            },
            required=['username', 'email', 'password'],
        ),
        responses={
            201: "Utilisateur créé avec succès",
            400: "Données invalides"
        }
    )
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Utilisateur créé avec succès"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

def revoke_all_user_tokens(user: User):
    """Révoque tous les refresh tokens d'un utilisateur (sauvegarde en base)."""
    RefreshToken.objects.filter(user=user, revoked=False).update(revoked=True)


# -----------------------------------------
# Refresh avec rotation + détection de reuse
# -----------------------------------------
class RefreshView(APIView):
    @swagger_auto_schema(
        operation_summary="Rafraîchir les tokens d’un utilisateur",
        operation_description="Permet de rafraîchir les tokens d'accès et de refresh en fournissant un refresh token valide.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'refresh': openapi.Schema(type=openapi.TYPE_STRING, example="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."),
            },
            required=['refresh'],
        ),
        responses={
            200: openapi.Response(
                description="Tokens rafraîchis avec succès",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'access': openapi.Schema(type=openapi.TYPE_STRING),
                        'refresh': openapi.Schema(type=openapi.TYPE_STRING),
                    }
                )
            ),
            401: "Token invalide ou réutilisé",
            400: "Requête invalide"
        }
    )

    def post(self, request):
        refresh_token = request.data.get("refresh")
        if not refresh_token:
            return Response({"detail": "refresh token required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            payload = decode_jwt(refresh_token)
        except Exception as e:
            return Response({"detail": "Invalid or malformed token"}, status=status.HTTP_401_UNAUTHORIZED)

        # Vérifier que c'est bien un refresh token
        if payload.get("type") != "refresh":
            return Response({"detail": "Token is not a refresh token"}, status=status.HTTP_401_UNAUTHORIZED)

        jti = payload.get("jti")
        user_id = payload.get("user_id")

        if not jti or not user_id:
            return Response({"detail": "Invalid token payload"}, status=status.HTTP_401_UNAUTHORIZED)

        # Hash fourni
        token_hash = hash_token(refresh_token)

        # Chercher l'entrée en DB par jti
        try:
            token_obj = RefreshToken.objects.get(jti=jti)
        except RefreshToken.DoesNotExist:
            # Pas trouvé => possible token invalide ou déjà supprimé -> treat as invalid
            return Response({"detail": "Refresh token not found"}, status=status.HTTP_401_UNAUTHORIZED)

        # Si la hash ne correspond pas => possible token reuse (quelqu'un réutilise un token ancien)
        if token_obj.token_hash != token_hash or token_obj.revoked:
            # Sécurité : révoquer tous les tokens de l'utilisateur (compromission possible)
            try:
                user = User.objects.get(pk=user_id)
                revoke_all_user_tokens(user)
            except User.DoesNotExist:
                pass
            return Response({"detail": "Refresh token reuse or revoked. All sessions invalidated."},
                            status=status.HTTP_401_UNAUTHORIZED)

        # Vérifier expiration
        if token_obj.is_expired():
            token_obj.revoke()
            return Response({"detail": "Refresh token expired"}, status=status.HTTP_401_UNAUTHORIZED)

        # Rotation : transaction pour éviter état intermédiaire
        with transaction.atomic():
            # révoquer l'ancien
            token_obj.revoke()

            # créer nouveaux tokens
            new_access = make_access_token(user_id)
            new_refresh = make_refresh_token(user_id)

            # décoder pour récupérer jti et exp
            try:
                decoded_new_refresh = decode_jwt(new_refresh)
            except Exception:
                return Response({"detail": "Failed to create new refresh token"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            new_jti = decoded_new_refresh.get("jti")
            exp_ts = decoded_new_refresh.get("exp")
            expires_at = timezone.datetime.fromtimestamp(exp_ts, tz=timezone.utc)

            # stocker hash du nouveau refresh
            RefreshToken.objects.create(
                user=token_obj.user,
                jti=new_jti,
                token_hash=hash_token(new_refresh),
                expires_at=expires_at
            )

        return Response({"access": new_access, "refresh": new_refresh}, status=status.HTTP_200_OK)


# -----------------------------------------
# Logout
# -----------------------------------------
class LogoutView(APIView):

    @swagger_auto_schema(
        operation_summary="Révoquer des tokens",
        operation_description="Permet de révoquer un refresh token spécifique ou tous les tokens d'un utilisateur en fournissant un refresh token valide.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'refresh': openapi.Schema(type=openapi.TYPE_STRING, example="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."),
                'all': openapi.Schema(type=openapi.TYPE_BOOLEAN, example=True),
            },
            required=['refresh'],
        ),
        responses={
            200: "Tokens révoqués avec succès",
            400: "Requête invalide",
            401: "Token invalide ou réutilisé"
        }
    )
    def post(self, request):
        refresh_token = request.data.get("refresh")
        revoke_all_flag = request.data.get("all", False)

        if not refresh_token and not revoke_all_flag:
            return Response({"detail": "refresh token required (or set all=true to revoke all sessions)"}, status=status.HTTP_400_BAD_REQUEST)

        # Si on veut révoquer tous les tokens, on vérifie d'abord la validité du refresh fourni
        try:
            payload = decode_jwt(refresh_token)
        except Exception:
            return Response({"detail": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

        if payload.get("type") != "refresh":
            return Response({"detail": "Provided token is not a refresh token"}, status=status.HTTP_401_UNAUTHORIZED)

        jti = payload.get("jti")
        user_id = payload.get("user_id")

        # Chercher le token en DB
        try:
            token_obj = RefreshToken.objects.get(jti=jti)
        except RefreshToken.DoesNotExist:
            # Si on n'a pas d'entrée, on considère que c'est invalide
            return Response({"detail": "Refresh token not found"}, status=status.HTTP_401_UNAUTHORIZED)

        # Vérifier que le hash correspond (prévenir les appels malicieux)
        if token_obj.token_hash != hash_token(refresh_token):
            # Même politique : révoquer tous les tokens de l'utilisateur si suspicion d'abus
            try:
                user = User.objects.get(pk=user_id)
                revoke_all_user_tokens(user)
            except User.DoesNotExist:
                pass
            return Response({"detail": "Token mismatch — all sessions invalidated"}, status=status.HTTP_401_UNAUTHORIZED)

        if revoke_all_flag:
            # Révoquer tous
            revoke_all_user_tokens(token_obj.user)
            return Response({"detail": "All sessions revoked"}, status=status.HTTP_200_OK)
        else:
            # Révoquer seulement ce refresh token
            token_obj.revoke()
            return Response({"detail": "Refresh token revoked"}, status=status.HTTP_200_OK)