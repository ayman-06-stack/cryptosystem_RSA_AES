from cryptography.hazmat.primitives.asymmetric import rsa, dh
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

class CryptoSystem:
    def __init__(self, parameters=None):
        # RSA (Identité)
        self.private_key_rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key_rsa = self.private_key_rsa.public_key()
        
        # Diffie-Hellman (Accord de clé)
        # On utilise les paramètres partagés ou on en crée de nouveaux
        self.parameters = parameters if parameters else dh.generate_parameters(generator=2, key_size=1024)
        self.private_key_dh = self.parameters.generate_private_key()
        self.public_key_dh = self.private_key_dh.public_key()

    def get_dh_public_bytes(self):
        """Exporte la clé publique DH au format PEM"""
        return self.public_key_dh.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def generate_shared_aes_key(self, peer_public_key_bytes):
        """Calcule le secret partagé DH et le dérive en clé AES de 32 octets"""
        peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes)
        shared_key = self.private_key_dh.exchange(peer_public_key)
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'session-encryption',
        ).derive(shared_key)

    def encrypt_with_aes(self, key, plaintext):
        """Chiffrement AES-GCM (Authentifié)"""
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
        return nonce, ciphertext

    def decrypt_with_aes(self, key, nonce, ciphertext):
        """Déchiffrement AES-GCM avec clé DH"""
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None).decode()
    
    def decrypt_with_manual_key(self, manual_key_str, nonce, ciphertext):
        """Déchiffrement avec une clé textuelle saisie manuellement"""
        # Hachage de la chaîne pour garantir une clé de 32 octets (SHA-256)
        digest = hashes.Hash(hashes.SHA256())
        digest.update(manual_key_str.encode())
        key = digest.finalize()
        print(f"CLÉ DÉRIVÉE (MANUELLE) : {key.hex()}")
        
        aesgcm = AESGCM(key)
        # Le déchiffrement peut lever une exception si la clé est mauvaise
        return aesgcm.decrypt(nonce, ciphertext, None).decode()
    
    def encrypt_with_manual_key_logic(self, manual_key_str, plaintext):
        """Chiffrement avec une clé textuelle saisie manuellement"""
        # On hache pour avoir 32 octets (exactement comme au déchiffrement)
        digest = hashes.Hash(hashes.SHA256())
        digest.update(manual_key_str.encode())
        key = digest.finalize()
        
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
        return nonce, ciphertext