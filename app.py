from flask import Flask, render_template, request, jsonify, session
from crypto_logic import CryptoSystem 
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
import base64
import secrets
from datetime import datetime

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# --- INITIALISATION GLOBALE ---
print("Initialisation du système...")

# Génération des paramètres DH partagés
shared_params = dh.generate_parameters(generator=2, key_size=1024)

# Instances d'ayman et loukman
ayman = CryptoSystem(parameters=shared_params)
loukman = CryptoSystem(parameters=shared_params)

print("Système prêt (ayman et loukman partagent les mêmes paramètres DH) !")
print(f"Clé publique ayman (DH): {base64.b64encode(ayman.get_dh_public_bytes()).decode()[:50]}...")
print(f"Clé publique loukman (DH): {base64.b64encode(loukman.get_dh_public_bytes()).decode()[:50]}...")

# Stockage des messages avec toutes les infos crypto
chat_messages = []

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/select_user')
def select_user():
    return render_template('select_user.html')

@app.route('/chat/<username>')
def chat_page(username):
    if username not in ['ayman', 'loukman']:
        return "Utilisateur invalide", 404
    session['username'] = username
    return render_template('chat.html', username=username)

@app.route('/exchange_dh', methods=['GET'])
def exchange_dh():
    """Échange de clés publiques DH"""
    ayman_pub = ayman.get_dh_public_bytes()
    loukman_pub = loukman.get_dh_public_bytes()
    return jsonify({
        "status": "Success",
        "ayman_pub_dh": base64.b64encode(ayman_pub).decode(),
        "loukman_pub_dh": base64.b64encode(loukman_pub).decode()
    })

@app.route('/get_encryption_info', methods=['GET'])
def get_encryption_info():
    """Informations cryptographiques détaillées"""
    username = session.get('username', 'ayman')
    
    if username == 'ayman':
        user_system = ayman
        peer_system = loukman
        peer_name = "loukman"
    else:
        user_system = loukman
        peer_system = ayman
        peer_name = "ayman"
    
    # Calculer la clé partagée
    shared_key = user_system.generate_shared_aes_key(peer_system.get_dh_public_bytes())
    
    # Obtenir la clé privée DH (pour démonstration seulement)
    private_key_dh_numbers = user_system.private_key_dh.private_numbers()
    
    return jsonify({
        'username': username.upper(),
        'peer_name': peer_name,
        'my_public_key_dh': base64.b64encode(user_system.get_dh_public_bytes()).decode(),
        'peer_public_key_dh': base64.b64encode(peer_system.get_dh_public_bytes()).decode(),
        'shared_key_preview': shared_key.hex()[:64] + "...",
        'shared_key_full': shared_key.hex(),
        'private_key_value': str(private_key_dh_numbers.x)[:50] + "...",  # Valeur privée (pour démo)
        'algorithm': 'AES-256-GCM',
        'key_exchange': 'Diffie-Hellman (1024 bits)',
        'hash_function': 'SHA-256 (HKDF)'
    })

@app.route('/receiver')
def receiver_page():
    """Page de réception pour déchiffrement"""
    return render_template('receiver.html')

@app.route('/secure_send', methods=['POST'])
def secure_send():
    """Envoi sécurisé avec toutes les infos crypto"""
    try:
        data = request.json
        message = data.get('message')
        sender = data.get('sender', 'ayman')
        
        # Sélectionner l'expéditeur et le destinataire
        if sender == 'ayman':
            sender_sys = ayman
            receiver_sys = loukman
        else:
            sender_sys = loukman
            receiver_sys = ayman
        
        # Générer la clé partagée et chiffrer
        shared_key = sender_sys.generate_shared_aes_key(receiver_sys.get_dh_public_bytes())
        nonce, ciphertext = sender_sys.encrypt_with_aes(shared_key, message)
        
        # Stocker avec toutes les infos
        chat_messages.append({
            'sender': sender,
            'plaintext': message,  # Message en clair (pour démo)
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'nonce': base64.b64encode(nonce).decode(),
            'timestamp': datetime.now().isoformat(),
            'shared_key': shared_key.hex()[:64] + "...",
            'sender_public_key': base64.b64encode(sender_sys.get_dh_public_bytes()).decode()[:50] + "..."
        })
        
        print(f"\n{'='*80}")
        print(f" NOUVEAU MESSAGE - {sender.upper()}")
        print(f"{'='*80}")
        print(f"Message clair: {message}")
        print(f" Clé AES partagée: {shared_key.hex()[:64]}...")
        print(f" Nonce (12 octets): {base64.b64encode(nonce).decode()}")
        print(f" Message chiffré: {base64.b64encode(ciphertext).decode()[:80]}...")
        print(f"{'='*80}\n")
        
        return jsonify({
            'status': 'success',
            'message_id': len(chat_messages) - 1,
            'ciphertext_preview': base64.b64encode(ciphertext).decode()[:50] + "..."
        })
    except Exception as e:
        print(f" Erreur secure_send: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/get_messages', methods=['GET'])
def get_messages():
    """Récupère les messages avec toutes les infos crypto"""
    try:
        user = request.args.get('user', 'ayman')
        
        # Sélectionner le déchiffreur
        if user == 'ayman':
            decryptor = ayman
            peer = loukman
        else:
            decryptor = loukman
            peer = ayman
        
        # Générer la clé partagée
        shared_key = decryptor.generate_shared_aes_key(peer.get_dh_public_bytes())
        
        # Préparer les messages avec infos crypto
        enriched_messages = []
        for msg in chat_messages:
            try:
                # Vérifier le déchiffrement (même si on a le plaintext stocké)
                nonce = base64.b64decode(msg['nonce'])
                ciphertext = base64.b64decode(msg['ciphertext'])
                decrypted_text = decryptor.decrypt_with_aes(shared_key, nonce, ciphertext)
                
                enriched_messages.append({
                    'text': msg['plaintext'],  # Message clair original
                    'sender': msg['sender'],
                    'timestamp': msg.get('timestamp', ''),
                    'ciphertext': msg['ciphertext'],
                    'nonce': msg['nonce'],
                    'shared_key_used': msg.get('shared_key', 'N/A'),
                    'decryption_success': decrypted_text == msg['plaintext']
                })
            except Exception as e:
                print(f"⚠️ Erreur traitement message: {e}")
                continue
        
        return jsonify({
            'messages': enriched_messages,
            'status': 'success',
            'total': len(enriched_messages)
        })
    except Exception as e:
        print(f"❌ Erreur get_messages: {e}")
        return jsonify({'error': str(e), 'messages': []}), 500

# --- ROUTES SUPPLÉMENTAIRES ---

@app.route('/decrypt', methods=['POST'])
def decrypt():
    """Déchiffrement manuel"""
    try:
        data = request.json
        username = session.get('username', 'loukman')
        
        if username == 'ayman':
            decryptor = ayman
            sender = loukman
        else:
            decryptor = loukman
            sender = ayman
        
        key = decryptor.generate_shared_aes_key(sender.get_dh_public_bytes())
        nonce = base64.b64decode(data['nonce'])
        ciphertext = base64.b64decode(data['ciphertext'])
        
        msg = decryptor.decrypt_with_aes(key, nonce, ciphertext)
        
        return jsonify({'message': msg})
    except Exception as e:
        return jsonify({"error": "Échec du déchiffrement"}), 500

@app.route('/encrypt_manual', methods=['POST'])
def encrypt_manual():
    """Chiffrement avec mot de passe"""
    try:
        data = request.json
        msg = data.get('message')
        password = data.get('manual_key')
        username = session.get('username', 'ayman')
        
        sender = ayman if username == 'ayman' else loukman
        nonce, ciphertext = sender.encrypt_with_manual_key_logic(password, msg)
        
        return jsonify({
            'nonce': base64.b64encode(nonce).decode(),
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'encryption_key': password
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/decrypt_manual', methods=['POST'])
def decrypt_manual():
    """Déchiffrement avec mot de passe"""
    try:
        data = request.json
        manual_key = data.get('manual_key')
        nonce = base64.b64decode(data['nonce'])
        ciphertext = base64.b64decode(data['ciphertext'])
        username = session.get('username', 'loukman')
        
        decryptor = loukman if username == 'loukman' else ayman
        msg = decryptor.decrypt_with_manual_key(manual_key, nonce, ciphertext)
        
        return jsonify({'message': msg})
    except Exception as e:
        return jsonify({"error": "Mot de passe incorrect"}), 400

@app.route('/clear_chat', methods=['POST'])
def clear_chat():
    """Effacer tous les messages"""
    global chat_messages
    chat_messages = []
    return jsonify({"status": "cleared"})

@app.route('/get_crypto_details', methods=['GET'])
def get_crypto_details():
    """Détails cryptographiques complets pour la démo"""
    username = session.get('username', 'ayman')
    
    if username == 'ayman':
        user_sys = ayman
        peer_sys = loukman
    else:
        user_sys = loukman
        peer_sys = ayman
    
    shared_key = user_sys.generate_shared_aes_key(peer_sys.get_dh_public_bytes())
    
    # Extraire les nombres DH
    my_private_numbers = user_sys.private_key_dh.private_numbers()
    my_public_numbers = user_sys.public_key_dh.public_numbers()
    peer_public_numbers = peer_sys.public_key_dh.public_numbers()
    
    return jsonify({
        'user': username.upper(),
        'dh_parameters': {
            'generator': my_public_numbers.parameter_numbers.g,
            'prime_modulus_bits': 1024,
            'prime_modulus_preview': str(my_public_numbers.parameter_numbers.p)[:100] + "..."
        },
        'my_keys': {
            'private_key_x': str(my_private_numbers.x)[:80] + "...",
            'public_key_y': str(my_public_numbers.y)[:80] + "...",
            'public_key_pem': base64.b64encode(user_sys.get_dh_public_bytes()).decode()
        },
        'peer_keys': {
            'public_key_y': str(peer_public_numbers.y)[:80] + "...",
            'public_key_pem': base64.b64encode(peer_sys.get_dh_public_bytes()).decode()
        },
        'shared_secret': {
            'aes_key_hex': shared_key.hex(),
            'aes_key_length': len(shared_key),
            'derivation_function': 'HKDF-SHA256'
        }
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)