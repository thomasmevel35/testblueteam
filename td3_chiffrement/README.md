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
- Chiffrement récursif + barre de progression avec pourcentage

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

---

## Interface de chiffrement (avec pourcentage)

Lors du chiffrement, le script affiche une progression en temps réel:

```text
Chiffrement de 15 fichiers...
[██████████████      ] 73% - rapport_2024.pdf
```

En fin d'opération, un résumé est affiché:

```text
Résultat: total=15, chiffrés=14, ignorés=1, erreurs=0
✓ Dossier traité avec succès.
```

---

## SFTP (connexion) - version refaite

### Format de connexion

- Cible standard: `utilisateur@ip_ou_hote`
- IPv6 accepté: `utilisateur@[2001:db8::1]`

### Ce que fait le module SFTP

- Validation de la cible et du port
- Connexion via `paramiko.SSHClient` (plus compatible selon les serveurs SFTP)
- Validation de l'authentification (mot de passe ou clé privée `key_filename`)
- Vérification du fichier local avant envoi
- Création automatique des dossiers distants intermédiaires
- Vérification de la taille distante après upload (contrôle d'intégrité simple)

### Exemples

#### Exemple 1 — mot de passe

```text
Choix : 2
Chemin de la clé locale : /home/user/.local/share/td3_keys/key_aes_256_20260211_120000.json
Chemin distant de destination : /home/backup/keys/key_aes_256_20260211_120000.json
Connexion SFTP (utilisateur@ip_ou_hote) : admin@192.168.1.20
Port SFTP [22] : 22
Auth [1=mot de passe, 2=clé privée] : 1
Mot de passe : ********
✓ Transfert SFTP réussi.
✓ Sauvegarde de clé distante terminée.
```

#### Exemple 2 — clé privée SSH

```text
Choix : 2
Chemin de la clé locale : /home/user/.local/share/td3_keys/key_pbkdf2_256_20260211_121500.json
Chemin distant de destination : /srv/secure/keys/key_pbkdf2_256_20260211_121500.json
Connexion SFTP (utilisateur@ip_ou_hote) : backup@fileserver.local
Port SFTP [22] : 2222
Auth [1=mot de passe, 2=clé privée] : 2
Chemin de la clé privée SSH : /home/user/.ssh/id_rsa
✓ Transfert SFTP réussi.
✓ Sauvegarde de clé distante terminée.
```

#### Exemple 3 — IPv6

```text
Connexion SFTP (utilisateur@ip_ou_hote) : ops@[2001:db8::10]
```

---

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
