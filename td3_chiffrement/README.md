# TD3 - Système de Chiffrement Défensif

> ⚠️ Ce projet est un outil pédagogique **défensif** de protection de fichiers avec consentement explicite. Il ne doit pas être utilisé à des fins malveillantes.

## Structure

```bash
td3_chiffrement/
├── main.py
├── requirements.txt
└── README.md
```

## Fonctionnalités

- Vérification des dépendances (`check_dependencies`)
- Génération de clés (AES aléatoire ou dérivée PBKDF2) (`generate_key`)
- Sauvegarde sécurisée de clés en JSON (`save_key`)
- Transfert sécurisé de clé via SFTP (`send_sftp`)
- Chiffrement de fichier en-place ou en sortie `.enc` (`encrypt_file`)
- Sélection interactive de fichiers/dossiers (`select_directories`)
- Chiffrement récursif et barre de progression texte

## Installation

```bash
python3 -m pip install -r requirements.txt
```

## Utilisation

```bash
python3 main.py
```

Menu principal:

1. Générer une nouvelle clé
2. Envoyer une clé via SFTP
3. Chiffrer des fichiers/dossiers
4. Vérifier les dépendances
5. Quitter

## Notes sécurité

- Les clés sont enregistrées par défaut dans:
  - Linux: `/var/keys` (fallback auto vers `~/.local/share/td3_keys` si non-root)
  - Windows: `C:\ProgramData\td3_keys`
- Permissions de fichier visées: `600` (si possible)
- Le mot de passe PBKDF2 n'est jamais stocké en clair
- Format des fichiers chiffrés: `MAGIC + nonce + ciphertext` (AES-GCM)

## Limites

- Ce script implémente le chiffrement uniquement (pas de déchiffrement).
- Pour les chemins système (`/var/keys`), des droits administrateur peuvent être nécessaires.
