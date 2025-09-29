## Explication pédagogique

Ce projet illustre un flux simple de chiffrement/déchiffrement avec un mot de passe. Il s’appuie sur `cryptography` (Fernet) et une dérivation de clé par PBKDF2.

### Fonctions principales

- `derive_key_from_password(password: str) -> bytes`
  - Dérive une clé à partir d’un mot de passe avec un sel démonstratif fixe (usage pédagogique uniquement). Les fonctions de chiffrement et déchiffrement utilisent, elles, un sel aléatoire stocké dans le fichier chiffré.

- `_derive_key_with_salt(password: str, salt: bytes) -> bytes`
  - Dérive la clé via PBKDF2-HMAC-SHA256 avec un nombre d’itérations élevé, puis encode la clé en Base64 URL-safe pour Fernet. Utilisée en interne.

- `encrypt_file(input_path: str, output_path: str, password: str) -> None`
  - Vérifie l’existence du fichier, lit les octets, génère un `salt` aléatoire, dérive la clé, chiffre via `Fernet`, et écrit `MAGIC + SALT + TOKEN` dans `output_path`.

- `decrypt_file(input_path: str, output_path: str, password: str) -> None`
  - Vérifie le format `MAGIC`, extrait le `salt`, dérive la clé, tente de déchiffrer le `TOKEN` Fernet, et écrit le résultat en clair.

- `parse_args() -> argparse.Namespace`
  - Définit l’interface CLI avec deux sous-commandes: `encrypt` et `decrypt`, chacune recevant `--input` et `--output`.

- `main() -> None`
  - Orchestration: lit le mot de passe via `getpass.getpass()`, appelle la fonction correspondant à la sous-commande, gère les erreurs, et affiche un message de succès.

### Flux d’exécution global

1. L’utilisateur appelle `encrypt` ou `decrypt` avec `--input` et `--output`.
2. Le programme demande le mot de passe sans l’afficher.
3. Pour `encrypt`: lecture → dérivation (sel aléatoire) → chiffrement → écriture du fichier chiffré.
4. Pour `decrypt`: lecture → vérification/parse → dérivation (sel extrait) → déchiffrement → écriture du fichier déchiffré.

### Principe de Fernet (brièvement)

Fernet définit un format standardisé pour le chiffrement authentifié symétrique (basé sur AES en mode CBC/CTR et HMAC, géré par la bibliothèque). Il fournit une API simple: `encrypt(plaintext)` et `decrypt(token)`. La clé Fernet est une chaîne Base64 de 32 octets. Ici, on dérive cette clé à partir d’un mot de passe via PBKDF2 pour éviter d’utiliser directement le mot de passe brut.

> Note: Même si Fernet est sûr lorsqu’il est bien utilisé, ce projet reste un exercice d’initiation. En production, il faut intégrer des pratiques supplémentaires (gestion de clés, menace, rotation, etc.).


