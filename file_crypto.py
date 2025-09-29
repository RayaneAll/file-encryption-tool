#!/usr/bin/env python3
"""
Nom: file_crypto.py
Description: Script CLI simple pour chiffrer et déchiffrer des fichiers à l'aide
de mots de passe et de la bibliothèque cryptography (Fernet + PBKDF2).
Auteur: Rayane Allaoui
Date: 2025

AVERTISSEMENT: Projet éducatif uniquement. Ne pas utiliser en production pour
des données sensibles. Vérifiez toujours la sécurité selon votre contexte.
Licence: MIT
"""

from __future__ import annotations

import argparse
import base64
import getpass
import os
import sys
from typing import Tuple

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# Constantes utilisées pour sérialiser le format de fichier chiffré.
# Format: MAGIC(4 octets) + SALT(16 octets) + FERNET_TOKEN(variable)
MAGIC_HEADER = b"FENC"
SALT_SIZE_BYTES = 16
PBKDF2_ITERATIONS = 390000  # Valeur recommandée moderne pour PBKDF2-HMAC-SHA256


def _derive_key_with_salt(password: str, salt: bytes) -> bytes:
    """Dérive une clé à partir d'un mot de passe et d'un sel via PBKDF2-HMAC-SHA256.

    Remarque: Fernet exige une clé de 32 octets en Base64 URL-safe.

    Paramètres:
        password: Mot de passe fourni par l'utilisateur (texte).
        salt: Sel aléatoire (bytes) utilisé pour la dérivation.

    Retour:
        Clé encodée en Base64 URL-safe (bytes) utilisable par Fernet.
    """

    # Convertir le mot de passe en bytes (UTF-8)
    password_bytes = password.encode("utf-8")

    # Construire le KDF PBKDF2 avec SHA256
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Taille de clé requise par Fernet
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )

    # Dériver la clé puis l'encoder en Base64 URL-safe pour Fernet
    derived_key = kdf.derive(password_bytes)
    return base64.urlsafe_b64encode(derived_key)


def derive_key_from_password(password: str) -> bytes:
    """Fonction demandée par la spécification (signature exacte).

    Cette fonction renvoie une clé dérivée d'un mot de passe à l'aide d'un sel
    fixe purement pédagogique. NE PAS utiliser ce résultat pour sécuriser des
    données sensibles. Les fonctions encrypt_file/decrypt_file utilisent un sel
    aléatoire distinct stocké avec le fichier chiffré (recommandé).

    Paramètres:
        password: Mot de passe (texte).

    Retour:
        Clé encodée en Base64 URL-safe (bytes) pour Fernet.
    """

    # Sel fixe pour démonstration (non utilisé pour le chiffrement réel ci-dessous)
    demo_salt = b"\x00" * SALT_SIZE_BYTES
    return _derive_key_with_salt(password, demo_salt)


def encrypt_file(input_path: str, output_path: str, password: str) -> None:
    """Lit un fichier, le chiffre avec Fernet et écrit le résultat.

    Étapes:
      1) Vérifier l'existence du fichier d'entrée.
      2) Lire tout le contenu en binaire.
      3) Générer un sel aléatoire et dériver la clé depuis le mot de passe.
      4) Chiffrer via Fernet.
      5) Écrire MAGIC + SALT + TOKEN vers le fichier de sortie.

    Lève des exceptions en cas d'erreur; la fonction main gère l'affichage.
    """

    # 1) Vérifier l'existence
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Fichier introuvable: {input_path}")

    # 2) Lecture binaire complète
    with open(input_path, "rb") as f_in:
        plaintext = f_in.read()

    # 3) Génération d'un sel aléatoire et dérivation de clé
    salt = os.urandom(SALT_SIZE_BYTES)
    key = _derive_key_with_salt(password, salt)
    fernet = Fernet(key)

    # 4) Chiffrement
    token = fernet.encrypt(plaintext)

    # 5) Sérialisation: MAGIC + SALT + TOKEN
    payload = MAGIC_HEADER + salt + token
    with open(output_path, "wb") as f_out:
        f_out.write(payload)


def decrypt_file(input_path: str, output_path: str, password: str) -> None:
    """Lit un fichier chiffré et écrit le contenu déchiffré.

    Étapes:
      1) Vérifier l'existence du fichier d'entrée.
      2) Lire tout le contenu en binaire.
      3) Vérifier l'en-tête et extraire le sel.
      4) Dériver la clé et tenter le déchiffrement.
      5) Écrire le texte en clair dans le fichier de sortie.

    Lève InvalidToken en cas de mot de passe incorrect ou fichier corrompu.
    """

    # 1) Vérifier l'existence
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Fichier introuvable: {input_path}")

    # 2) Lecture binaire complète
    with open(input_path, "rb") as f_in:
        data = f_in.read()

    # 3) Vérification de l'en-tête et extraction du sel
    if len(data) < len(MAGIC_HEADER) + SALT_SIZE_BYTES:
        raise ValueError("Fichier chiffré invalide ou incomplet.")

    header = data[: len(MAGIC_HEADER)]
    if header != MAGIC_HEADER:
        raise ValueError("Format de fichier invalide (signature incorrecte).")

    salt = data[len(MAGIC_HEADER) : len(MAGIC_HEADER) + SALT_SIZE_BYTES]
    token = data[len(MAGIC_HEADER) + SALT_SIZE_BYTES :]

    # 4) Dérivation de la clé et déchiffrement
    key = _derive_key_with_salt(password, salt)
    fernet = Fernet(key)
    plaintext = fernet.decrypt(token)  # Peut lever InvalidToken

    # 5) Écriture du contenu déchiffré
    with open(output_path, "wb") as f_out:
        f_out.write(plaintext)


def parse_args() -> argparse.Namespace:
    """Construit et analyse les arguments de la ligne de commande.

    Deux sous-commandes sont disponibles:
      - encrypt: chiffrer un fichier
      - decrypt: déchiffrer un fichier
    """

    parser = argparse.ArgumentParser(
        description=(
            "Chiffrement/Déchiffrement de fichiers (éducatif) avec mot de passe."
        )
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # Sous-commande: encrypt
    p_enc = subparsers.add_parser("encrypt", help="Chiffrer un fichier")
    p_enc.add_argument("--input", required=True, help="Chemin du fichier d'entrée")
    p_enc.add_argument(
        "--output", required=True, help="Chemin du fichier de sortie chiffré"
    )

    # Sous-commande: decrypt
    p_dec = subparsers.add_parser("decrypt", help="Déchiffrer un fichier")
    p_dec.add_argument("--input", required=True, help="Chemin du fichier chiffré")
    p_dec.add_argument(
        "--output", required=True, help="Chemin du fichier de sortie déchiffré"
    )

    return parser.parse_args()


def main() -> None:
    """Point d'entrée principal de la CLI.

    - Demande le mot de passe à l'utilisateur sans affichage.
    - Exécute l'opération demandée (encrypt/decrypt).
    - Affiche un message de succès ou une erreur claire.
    """

    args = parse_args()

    try:
        # Lecture sécurisée du mot de passe (non affiché)
        password = getpass.getpass("Mot de passe: ")

        if args.command == "encrypt":
            encrypt_file(args.input, args.output, password)
            print(f"Fichier chiffré avec succès : {args.output}")
        elif args.command == "decrypt":
            try:
                decrypt_file(args.input, args.output, password)
            except InvalidToken:
                # Mot de passe incorrect ou fichier corrompu
                print(
                    "Erreur: mot de passe incorrect ou fichier chiffré invalide.",
                    file=sys.stderr,
                )
                sys.exit(1)
            print(f"Fichier déchiffré avec succès : {args.output}")
        else:
            print("Commande inconnue.", file=sys.stderr)
            sys.exit(2)

    except FileNotFoundError as e:
        print(f"Erreur: {e}", file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        print(f"Erreur: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        # Message simple et propre pour toute autre exception
        print(f"Erreur inattendue: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()


