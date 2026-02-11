#!/usr/bin/env python3
"""Outil de chiffrement défensif pour TP3.

Ce script est conçu pour un usage légitime de protection de fichiers.
Il chiffre des fichiers localement avec consentement explicite de l'utilisateur.
"""

from __future__ import annotations

import base64
import getpass
import importlib.util
import json
import os
import platform
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Optional

MAGIC = b"TD3ENC1\n"
SUPPORTED_LENGTHS = {128: 16, 192: 24, 256: 32}

@lru_cache(maxsize=1)
def _load_crypto_primitives():
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    except ImportError as exc:
        raise RuntimeError(
            "La bibliothèque 'cryptography' est requise. Lancez l'option 4 du menu pour vérifier/installer les dépendances."
        ) from exc

    return hashes, AESGCM, PBKDF2HMAC


@dataclass
class KeyMaterial:
    """Conteneur de clé pour chiffrement."""

    algorithm: str
    length_bits: int
    key_bytes: bytes
    metadata: dict


def print_banner() -> None:
    print("=" * 40)
    print("Système de Chiffrement Défensif - TP3")
    print("=" * 40)


def check_dependencies() -> bool:
    """Vérifie Python et les bibliothèques requises, propose installation."""
    missing: list[str] = []

    if sys.version_info < (3, 8):
        print("✗ Python 3.8+ est requis.")
        return False

    required = ["cryptography", "paramiko"]
    for module in required:
        if importlib.util.find_spec(module) is None:
            missing.append(module)

    if not missing:
        print("✓ Dépendances OK (Python, cryptography, paramiko).")
        return True

    print(f"⚠ Dépendances manquantes: {', '.join(missing)}")
    choice = input("Installer automatiquement maintenant ? (O/N): ").strip().lower()
    if choice not in {"o", "oui", "y", "yes"}:
        print("Installation ignorée.")
        return False

    try:
        cmd = [sys.executable, "-m", "pip", "install", *missing]
        print("Exécution:", " ".join(cmd))
        subprocess.check_call(cmd)
        print("✓ Installation terminée.")
        return True
    except subprocess.CalledProcessError as exc:
        print(f"✗ Erreur d'installation: {exc}")
    except Exception as exc:  # noqa: BLE001
        print(f"✗ Erreur inattendue: {exc}")
    return False


def _default_key_dir() -> Path:
    if platform.system().lower().startswith("win"):
        return Path(os.environ.get("PROGRAMDATA", "C:/ProgramData")) / "td3_keys"
    return Path("/var/keys")


def generate_key(algo: str, length: int) -> KeyMaterial:
    """Génère une clé AES aléatoire ou dérivée PBKDF2."""
    if length not in SUPPORTED_LENGTHS:
        raise ValueError("Longueur invalide. Choisir 128, 192 ou 256 bits.")

    size_bytes = SUPPORTED_LENGTHS[length]
    normalized_algo = algo.strip().upper()

    hashes, AESGCM, PBKDF2HMAC = _load_crypto_primitives()

    if normalized_algo == "AES":
        key_bytes = AESGCM.generate_key(bit_length=length)
        metadata = {
            "created_at": datetime.utcnow().isoformat() + "Z",
            "source": "os_random",
        }
        return KeyMaterial("AES", length, key_bytes, metadata)

    if normalized_algo == "PBKDF2":
        passphrase = getpass.getpass("Entrez une phrase secrète (non affichée): ")
        if not passphrase:
            raise ValueError("Phrase secrète vide interdite.")
        iterations = 600_000
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=size_bytes,
            salt=salt,
            iterations=iterations,
        )
        key_bytes = kdf.derive(passphrase.encode("utf-8"))
        metadata = {
            "created_at": datetime.utcnow().isoformat() + "Z",
            "source": "pbkdf2",
            "salt_b64": base64.b64encode(salt).decode("ascii"),
            "iterations": iterations,
        }
        return KeyMaterial("PBKDF2", length, key_bytes, metadata)

    raise ValueError("Algorithme invalide. Choisir AES ou PBKDF2.")


def _linux_user_key_dir() -> Path:
    xdg_data_home = os.environ.get("XDG_DATA_HOME")
    if xdg_data_home:
        return Path(xdg_data_home) / "td3_keys"
    return Path.home() / ".local" / "share" / "td3_keys"


def save_key(key: KeyMaterial, path: Optional[Path] = None) -> Path:
    """Sauvegarde une clé en JSON avec permissions restreintes.

    Sous Linux, si `/var/keys` n'est pas accessible (non-root), un fallback est
    appliqué vers `~/.local/share/td3_keys`.
    """
    key_dir = path or _default_key_dir()
    try:
        key_dir.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        if path is not None:
            raise
        key_dir = _linux_user_key_dir()
        key_dir.mkdir(parents=True, exist_ok=True)
        print(f"⚠ Permissions insuffisantes pour /var/keys, fallback vers: {key_dir}")

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"key_{key.algorithm.lower()}_{key.length_bits}_{ts}.json"
    target = key_dir / filename

    payload = {
        "algorithm": key.algorithm,
        "length_bits": key.length_bits,
        "key_b64": base64.b64encode(key.key_bytes).decode("ascii"),
        "metadata": key.metadata,
    }

    with target.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)

    try:
        os.chmod(target, 0o600)
    except PermissionError:
        print("⚠ Permissions 600 non appliquées (droits insuffisants).")

    return target


def load_key(path: Path) -> KeyMaterial:
    with path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)

    return KeyMaterial(
        algorithm=data["algorithm"],
        length_bits=int(data["length_bits"]),
        key_bytes=base64.b64decode(data["key_b64"]),
        metadata=data.get("metadata", {}),
    )




def parse_sftp_target(target: str) -> tuple[str, str]:
    """Parse une cible SFTP au format `utilisateur@hote`.

    Supporte également la forme IPv6 entre crochets: `user@[2001:db8::1]`.
    Retourne `(username, host)`.
    """
    value = target.strip()
    if "@" not in value:
        raise ValueError("Format invalide. Utilisez utilisateur@ip_ou_hote.")

    username, host = value.split("@", 1)
    username = username.strip()
    host = host.strip()

    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1].strip()

    if not username or not host:
        raise ValueError("Format invalide. Utilisez utilisateur@ip_ou_hote.")

    return username, host


def _validate_sftp_config(config: dict) -> None:
    required = ["host", "port", "username"]
    for key in required:
        if not config.get(key):
            raise ValueError(f"Configuration SFTP incomplète: '{key}' manquant.")

    try:
        port = int(config["port"])
    except ValueError as exc:
        raise ValueError("Port SFTP invalide (entier attendu).") from exc

    if port < 1 or port > 65535:
        raise ValueError("Port SFTP invalide (1-65535).")

    if not config.get("password") and not config.get("private_key"):
        raise ValueError("Authentification requise: mot de passe ou clé privée.")


def _require_paramiko() -> None:
    if importlib.util.find_spec("paramiko") is None:
        raise RuntimeError(
            "La bibliothèque 'paramiko' est requise. Lancez l'option 4 du menu pour vérifier/installer les dépendances."
        )


def _prepare_remote_path(sftp_client, remote_path: str) -> str:
    """Crée les dossiers distants intermédiaires si nécessaire."""
    remote = remote_path.strip()
    if not remote:
        raise ValueError("Chemin distant vide.")

    parts = [p for p in remote.split("/") if p]
    if len(parts) <= 1:
        return remote

    dirs = parts[:-1]
    current = "/" if remote.startswith("/") else ""

    for folder in dirs:
        if current in {"", "/"}:
            current = f"{current}{folder}" if current == "/" else folder
        else:
            current = f"{current}/{folder}"

        try:
            sftp_client.stat(current)
        except OSError:
            sftp_client.mkdir(current)

    return remote


def send_sftp(local: str, remote: str, config: dict) -> bool:
    """Transfère un fichier de clé via SFTP (usage de sauvegarde)."""
    try:
        _require_paramiko()
        import paramiko

        local_path = Path(local).expanduser().resolve()
        if not local_path.is_file():
            raise FileNotFoundError(f"Fichier local introuvable: {local_path}")
        local_size = local_path.stat().st_size

        _validate_sftp_config(config)
        host = str(config["host"]).strip()
        port = int(config["port"])
        username = str(config["username"]).strip()

        connect_kwargs: dict = {"username": username}
        if config.get("password"):
            connect_kwargs["password"] = config["password"]
        else:
            key_path = Path(str(config["private_key"])).expanduser().resolve()
            if not key_path.is_file():
                raise FileNotFoundError(f"Clé privée SSH introuvable: {key_path}")
            connect_kwargs["pkey"] = paramiko.RSAKey.from_private_key_file(str(key_path))

        transport = paramiko.Transport((host, port))
        try:
            transport.connect(**connect_kwargs)
            with paramiko.SFTPClient.from_transport(transport) as sftp:
                final_remote = _prepare_remote_path(sftp, remote)
                sftp.put(str(local_path), final_remote)
                remote_stat = sftp.stat(final_remote)
                if remote_stat.st_size != local_size:
                    raise RuntimeError(
                        f"Transfert SFTP incomplet: taille distante {remote_stat.st_size} != taille locale {local_size}."
                    )
        finally:
            transport.close()

        print("✓ Transfert SFTP réussi.")
        return True
    except Exception as exc:  # noqa: BLE001
        print(f"✗ Erreur SFTP: {exc}")
        return False


def encrypt_file(filepath: str, key: bytes, inplace: bool = True) -> Path:
    """Chiffre un fichier avec AES-GCM.

    Format de sortie: MAGIC + nonce(12) + ciphertext.
    """
    if len(key) not in {16, 24, 32}:
        raise ValueError("Longueur de clé invalide pour AES-GCM (16/24/32 octets requis).")

    src = Path(filepath)
    if not src.is_file():
        raise FileNotFoundError(f"Fichier introuvable: {src}")

    _, AESGCM, _ = _load_crypto_primitives()

    data = src.read_bytes()
    aes = AESGCM(key)
    nonce = os.urandom(12)
    encrypted = aes.encrypt(nonce, data, None)
    payload = MAGIC + nonce + encrypted

    if inplace:
        dst = src
    else:
        dst = src.with_suffix(src.suffix + ".enc")

    dst.write_bytes(payload)
    return dst


def is_encrypted(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            header = fh.read(len(MAGIC))
        return header == MAGIC
    except OSError:
        return False


def collect_files_from_directory(root: Path, recursive: bool, extension_filter: str = "") -> list[Path]:
    iterator = root.rglob("*") if recursive else root.glob("*")
    ext_filter = ""
    if extension_filter:
        ext_filter = extension_filter if extension_filter.startswith(".") else f".{extension_filter}"
        ext_filter = ext_filter.lower()

    files: list[Path] = []
    for candidate in iterator:
        if not candidate.is_file():
            continue
        if ext_filter and candidate.suffix.lower() != ext_filter:
            continue
        files.append(candidate)

    return files


def parse_yes_no(value: str) -> bool:
    """Normalise une réponse utilisateur de type oui/non."""
    return value.strip().lower() in {"o", "y", "yes", "oui"}


def render_progress(current: int, total: int, width: int = 20) -> str:
    if total <= 0:
        return "[" + (" " * width) + "] 0%"
    done = int(width * current / total)
    bar = "█" * done + " " * (width - done)
    pct = int((current / total) * 100)
    return f"[{bar}] {pct}%"


def print_progress_line(current: int, total: int, label: str = "") -> None:
    """Affiche une barre de progression en ligne (pourcentage)."""
    suffix = f" - {label}" if label else ""
    line = f"\r{render_progress(current, total)}{suffix}"
    print(line, end="", flush=True)
    if current >= total:
        print()


def select_directories() -> tuple[list[Path], bool]:
    print("[1] Fichier unique")
    print("[2] Dossier complet")
    print("[3] Dossier avec filtre d'extension")
    mode = input("Sélection : ").strip()

    if mode == "1":
        file_path = Path(input("Chemin du fichier : ").strip()).expanduser()
        if not file_path.is_file():
            raise ValueError("Chemin de fichier invalide.")
        return [file_path], False

    if mode in {"2", "3"}:
        folder = Path(input("Chemin du dossier : ").strip()).expanduser()
        if not folder.is_dir():
            raise ValueError("Chemin de dossier invalide.")

        recursive = parse_yes_no(input("Chiffrement récursif ? (O/N) : "))
        ext = ""
        if mode == "3":
            ext = input("Extension (ex: txt, pdf) : ").strip()

        files = collect_files_from_directory(folder, recursive=recursive, extension_filter=ext)
        if not files:
            raise ValueError("Aucun fichier correspondant trouvé.")
        return files, True

    raise ValueError("Sélection invalide.")


def _ask_choice(prompt: str, valid: set[str]) -> str:
    while True:
        value = input(prompt).strip()
        if value in valid:
            return value
        print("Entrée invalide.")


def action_generate_key() -> None:
    algo = input("Algorithme (AES/PBKDF2) : ").strip().upper()
    length = int(_ask_choice("Longueur (128/192/256) : ", {"128", "192", "256"}))
    key = generate_key(algo, length)

    custom = input("Répertoire de sauvegarde (Entrée pour défaut) : ").strip()
    path = Path(custom).expanduser() if custom else None
    saved = save_key(key, path)
    print(f"✓ Clé générée et sauvegardée : {saved}")


def action_send_sftp() -> None:
    local = input("Chemin de la clé locale : ").strip()
    remote = input("Chemin distant de destination : ").strip()

    target = input("Connexion SFTP (utilisateur@ip_ou_hote) : ").strip()
    username, host = parse_sftp_target(target)
    port = input("Port SFTP [22] : ").strip() or "22"

    auth_mode = _ask_choice("Auth [1=mot de passe, 2=clé privée] : ", {"1", "2"})
    config: dict[str, str] = {"host": host, "port": port, "username": username}

    if auth_mode == "1":
        config["password"] = getpass.getpass("Mot de passe : ")
    else:
        config["private_key"] = input("Chemin de la clé privée SSH : ").strip()

    ok = send_sftp(local, remote, config)
    if ok:
        print("✓ Sauvegarde de clé distante terminée.")


def action_encrypt() -> None:
    files, from_dir = select_directories()
    key_file = Path(input("Fichier clé JSON : ").strip()).expanduser()
    key_material = load_key(key_file)

    inplace = parse_yes_no(input("Chiffrement in-place ? (O/N) : "))

    total = len(files)
    print(f"Chiffrement de {total} fichiers...")
    done = 0
    skipped = 0
    failed = 0

    for file_path in files:
        try:
            if is_encrypted(file_path):
                skipped += 1
            else:
                encrypt_file(str(file_path), key_material.key_bytes, inplace=inplace)
        except Exception:
            failed += 1
        finally:
            done += 1
            print_progress_line(done, total, file_path.name)

    print(f"Résultat: total={total}, chiffrés={total - skipped - failed}, ignorés={skipped}, erreurs={failed}")
    if from_dir:
        print("✓ Dossier traité avec succès.")
    else:
        print("✓ Fichier traité avec succès.")


def main() -> None:
    while True:
        print_banner()
        print("1. Générer une nouvelle clé")
        print("2. Envoyer une clé via SFTP")
        print("3. Chiffrer des fichiers/dossiers")
        print("4. Vérifier les dépendances")
        print("5. Quitter")

        choice = input("Choix : ").strip()
        try:
            if choice == "1":
                action_generate_key()
            elif choice == "2":
                action_send_sftp()
            elif choice == "3":
                action_encrypt()
            elif choice == "4":
                check_dependencies()
            elif choice == "5":
                print("Au revoir.")
                return
            else:
                print("Choix invalide.")
        except Exception as exc:  # noqa: BLE001
            print(f"✗ Erreur: {exc}")

        input("\nAppuyez sur Entrée pour revenir au menu...")


if __name__ == "__main__":
    main()
