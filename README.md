# Mini Blockchain P2P (Python)

Implémentation pédagogique d'une blockchain minimale fonctionnelle avec:
- wallets (clés privées/publiques + adresses),
- signatures de transactions,
- validation de chaîne,
- PoW simplifié,
- réseau P2P minimal (diffusion + anti-boucle),
- tests automatisés.

## 1) Démarrage du projet

### Prérequis
- Python 3.10+

### Installation (venv)
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Exécuter les tests
```bash
pytest -q
```

## 2) Structure

```text
src/
  crypto/
    hash_utils.py      # hash SHA-256 + merkle root simplifié
    wallet.py          # génération clés, adresses, signatures
  core/
    models.py          # Transaction, BlockHeader, Block
    tx_service.py      # création/signature transaction
    blockchain.py      # Chain, State, validation, PoW, sélection chaîne
    contract.py        # exécution déterministe d'un contrat minimal
  p2p/
    node.py            # nœud réseau TCP, diffusion, synchronisation
    simulator.py       # simulateur réseau pour tests
    run_node.py        # lancement d'un nœud

tests/
  test_crypto.py
  test_blockchain.py
  test_p2p.py
  test_contract.py
```

## 3) Modèle de données minimal

- `Transaction(sender, recipient, amount, nonce, public_key, signature, tx_id)`
- `BlockHeader(index, previous_hash, merkle_root, timestamp, nonce, difficulty)`
- `Block(header, transactions, block_hash)`
- `Chain`: liste de blocs
- `State`: balances + nonces

## 4) Hashing et intégrité

- Hash transaction: SHA-256 JSON canonique (`tx_id`).
- Merkle root simplifié: hash pairwise des transactions.
- Intégrité bloc: hash du header+transactions + lien vers `previous_hash`.

## 5) Règles de validation

- Validation transaction:
  - montant > 0,
  - adresse émetteur dérivée de la clé publique,
  - signature valide,
  - nonce exact attendu,
  - solde suffisant.
- Validation bloc:
  - index consécutif,
  - `previous_hash` cohérent,
  - merkle root cohérente,
  - hash du bloc valide,
  - hash respecte la difficulté.
- Validation chaîne:
  - chaque bloc valide vis-à-vis du précédent.
- Règle de sélection:
  - remplacement par une chaîne **strictement plus longue** et valide.

## 6) Wallets et identités

- Génération de clé privée/publique: ECDSA secp256k1.
- Adresse dérivée: `sha256(public_key)` tronquée 20 octets (hex).

## 7) Signatures et anti-rejeu

- Signature côté client via la clé privée.
- Vérification côté nœud via la clé publique.
- Prévention rejeu:
  - `nonce` par compte,
  - `tx_id` unique (`seen_tx_ids`).

## 8) Réseau P2P minimal

- Découverte: ajout manuel de pairs (`--peer host:port`).
- Diffusion:
  - messages transaction,
  - messages bloc,
  - annonce de pair,
  - synchronisation chaîne (`chain`).
- Anti-boucle:
  - cache `seen_messages` basé sur `message id`.

## 9) Consensus minimal (classe)

- PoW simplifié: recherche d'un nonce tel que `hash(block)` commence par `difficulty` zéros.

## 10) Démonstration reproductible (3 nœuds)

Terminal 1:
```bash
PYTHONPATH=src python -m p2p.run_node --port 7001 --peer 127.0.0.1:7002 --peer 127.0.0.1:7003
```

Terminal 2:
```bash
PYTHONPATH=src python -m p2p.run_node --port 7002 --peer 127.0.0.1:7001 --peer 127.0.0.1:7003
```

Terminal 3:
```bash
PYTHONPATH=src python -m p2p.run_node --port 7003 --peer 127.0.0.1:7001 --peer 127.0.0.1:7002
```

Ensuite, via script Python/REPL:
1. créer 2 wallets,
2. créditer un wallet dans l'état,
3. créer transaction signée,
4. diffuser transaction,
5. miner un bloc,
6. diffuser bloc,
7. vérifier que l'état se met à jour sur les nœuds.

## 11) Commandes utiles

```bash
# lancer les tests
pytest -q

# format de lancement d'un nœud
PYTHONPATH=src python -m p2p.run_node --port 7001 --peer 127.0.0.1:7002
```
