# Cryptosystème Hybride : RSA, Diffie-Hellman & AES-GCM

## Description du Projet
Ce projet implémente un système de communication sécurisée de bout en bout basé sur une architecture cryptographique hybride. L'application utilise Flask pour le backend et la bibliothèque `cryptography` pour assurer la confidentialité, l'intégrité et l'authenticité des échanges entre deux entités distinctes.

L'objectif est de démontrer l'intégration de protocoles asymétriques pour l'établissement de clés et de protocoles symétriques pour le transport sécurisé des données.

## Spécifications Techniques

### Couche Cryptographique
* **Identité et Signature** : Utilisation de RSA avec des clés de 2048 bits pour l'identification des utilisateurs.
* **Accord de Clé** : Protocole Diffie-Hellman (DH) avec des paramètres partagés (g=2, 1024 bits) pour générer un secret partagé sans transmission directe.
* **Dérivation de Clé (KDF)** : Utilisation de HKDF avec l'algorithme SHA-256 pour dériver une clé de session de 32 octets à partir du secret DH.
* **Chiffrement Symétrique** : AES-256 en mode GCM (Authenticated Encryption) utilisant des nonces de 12 octets générés de manière aléatoire.

### Pile Technologique
* **Backend** : Flask (Python) pour la gestion des routes API et de la logique métier.
* **Frontend** : Interfaces web HTML5/CSS3 dynamiques avec JavaScript (Fetch API).
* **Sécurité** : Gestion des sessions sécurisées et isolation des contextes de chiffrement par utilisateur.

## Structure de l'Application
* `app.py` : Serveur central gérant l'échange de clés DH et le stockage temporaire des messages.
* `crypto_logic.py` : Classe `CryptoSystem` encapsulant les primitives de chiffrement, déchiffrement et dérivation de clés.
* `select_user.html` : Interface de sélection d'identité (Ayman ou Loukman).
* `chat.html` : Console de messagerie interactive avec visualisation en temps réel des métadonnées cryptographiques (Ciphertext, Nonce, Clés).
* `index.html` : Module de test permettant de simuler manuellement le chiffrement par mot de passe ou via DH.
* `receiver.html` : Fenêtre de réception isolée pour valider le déchiffrement côté destinataire.

## Installation et Déploiement

### Prérequis
* Python 3.8+
* Environnement virtuel (recommandé)

### Procédure
1. Installation des dépendances :
   ```bash
   pip install flask cryptography
