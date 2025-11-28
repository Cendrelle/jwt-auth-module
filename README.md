# 🔐 Django JWT Authentication Module

Module d’authentification **JWT autonome**, moderne et réutilisable pour Django.  
Ce module fournit :  
- Inscription  
- Connexion  
- Access Token + Refresh Token  
- Rotation sécurisée des tokens  
- Logout  
- Décodage + validation des tokens  
- Documentation interactive Swagger

Il est conçu pour être **intégré facilement dans n’importe quel projet Django**, sans dépendances inutiles.

---

## 🚀 Fonctionnalités

- Authentification complète basée sur **JWT HS256**
- Tokens courts (access) et longs (refresh)
- Rotation automatique des refresh token
- Stockage des refresh tokens hashés en base
- Endpoint sécurisé pour renouveler les tokens (`refresh`)
- Déconnexion avec invalidation du token
- Documentation Swagger disponible à l’adresse :


---

## 📦 Installation

Clone le projet :

```bash
git clone https://github.com/Cendrelle/jwt-auth-module.git
cd jwt-auth-module

## Installe les dépendances :

pip install -r requirements.txt


## Effectue les migrations :

python manage.py migrate


## Lance le serveur :

python manage.py runserver

## 🛠️ Intégration dans un autre projet Django

1️⃣ Copie le dossier jwt_auth/ dans un autre projet Django.

2️⃣ Ajoute-le dans INSTALLED_APPS :

INSTALLED_APPS = [
    ...
    'rest_framework',
    'drf_yasg',
    'jwt_auth',
]


3️⃣ Ajoute l’URL d’authentification dans ton urls.py :

path('api/auth/', include('jwt_auth.urls')),


C’est tout 🎉
Le module est prêt à être utilisé.

📚 Documentation Swagger (Auto-Générée)

Une documentation Swagger interactive est disponible à :

👉 /api/docs/

Elle contient :

Les endpoints (register, login, refresh, logout)

Les schémas de requêtes et réponses

Les types de tokens

Les codes d’erreur

Les exemples prêts à l’emploi

Ajouter Swagger (déjà configuré dans le module)

Dans jwt_auth/urls.py :

from drf_yasg.views import get_schema_view
from drf_yasg import openapi

schema_view = get_schema_view(
    openapi.Info(
        title="JWT Auth API",
        default_version='v1',
        description="Documentation de l’API d'authentification JWT",
    ),
    public=True,
)


Route pour afficher la doc :

path('docs/', schema_view.with_ui('swagger', cache_timeout=0), name='swagger-doc'),
