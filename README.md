## Chiffrement/Déchiffrement de fichiers — projet d’initiation (niveau 0)

Outil éducatif minimaliste en Python pour chiffrer et déchiffrer des fichiers (texte ou binaire) à partir d’un mot de passe. Basé sur `cryptography` (Fernet + PBKDF2).

⚠️ Important: usage éducatif uniquement. Ne pas utiliser pour des données sensibles en production.

### Prérequis

- Python 3.8+
- Installer les dépendances:

```bash
pip install cryptography
```

### Utilisation

Chiffrement:

```bash
python3 file_crypto.py encrypt --input chemin/vers/fichier --output chemin/vers/fichier_chiffre.enc
```

Déchiffrement:

```bash
python3 file_crypto.py decrypt --input chemin/vers/fichier_chiffre.enc --output chemin/vers/fichier_dechiffre
```

Le script demande un mot de passe via `getpass` (non affiché) puis écrit le résultat. Exemples de sortie:

```
Fichier chiffré avec succès : secret.enc
Fichier déchiffré avec succès : secret_decrypted.txt
```

### Détails techniques

- Le fichier chiffré contient `MAGIC(4) + SALT(16) + TOKEN(Fernet)`.
- La clé est dérivée via PBKDF2-HMAC-SHA256 (itérations élevées) et encodée Base64 URL-safe pour Fernet.
- Le sel aléatoire est stocké dans le fichier chiffré pour permettre la dérivation lors du déchiffrement.

### Exécution des tests

Installez `pytest` puis lancez:

```bash
pip install pytest cryptography
pytest -q
```

### Avertissements

- Projet académique et simplifié. Vérifiez et adaptez la sécurité à vos besoins réels.
- Sauvegardez vos fichiers avant toute opération.
- En cas de mot de passe incorrect, le déchiffrement échoue proprement.

### Licence

Ce projet est sous licence MIT (voir `LICENSE`).


