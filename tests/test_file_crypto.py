import os
import sys
import tempfile
from pathlib import Path

import pytest

# Assurer que la racine du projet est dans sys.path pour importer file_crypto
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from file_crypto import encrypt_file, decrypt_file


def test_encrypt_decrypt_roundtrip(tmp_path):
    # Contenu de test simple (avec caractères non ASCII pour vérifier l'encodage binaire)
    original_content = "Bonjour, chiffrons ceci: éàü 😊".encode("utf-8")

    # Fichiers temporaires
    input_file = tmp_path / "input.txt"
    encrypted_file = tmp_path / "output.enc"
    decrypted_file = tmp_path / "output.txt"

    # Écrire le fichier d'entrée
    input_file.write_bytes(original_content)

    # Mot de passe de test
    password = "motdepasse-test"

    # Chiffrer puis déchiffrer
    encrypt_file(str(input_file), str(encrypted_file), password)
    assert encrypted_file.exists()
    assert encrypted_file.read_bytes() != original_content

    decrypt_file(str(encrypted_file), str(decrypted_file), password)
    assert decrypted_file.exists()

    # Vérifier que le contenu est identique à l'original
    decrypted_content = decrypted_file.read_bytes()
    assert decrypted_content == original_content


def test_decrypt_with_wrong_password(tmp_path):
    original_content = b"secret"
    input_file = tmp_path / "input.bin"
    enc_file = tmp_path / "output.enc"
    dec_file = tmp_path / "output.bin"

    input_file.write_bytes(original_content)

    encrypt_file(str(input_file), str(enc_file), "correct-password")

    # Déchiffrement avec mauvais mot de passe doit lever une exception InvalidToken
    from cryptography.fernet import InvalidToken

    with pytest.raises(InvalidToken):
        decrypt_file(str(enc_file), str(dec_file), "wrong-password")


