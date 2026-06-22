# AeroShield: ZKP Privacy-Preserving Transactions

A simplified, self-contained privacy-preserving transaction system inspired by **Tornado Cash**. It uses zero-knowledge proof concepts to allow users to deposit funds using a secret note (hash commitment) and withdraw them to a fresh address anonymously, proving ownership without revealing the secret note.

## 🚀 Features

1. **Commitment Phase (Deposit)**:
   - Generates random credentials: a secret key $s$ and a nullifier $n$.
   - Computes a public key $Y = g^s \pmod p$.
   - Hashes them into a commitment $C = \text{SHA256}(Y || n)$ and inserts it as a leaf into a binary **Merkle Tree**.

2. **Proof Phase (ZKP Generation)**:
   - Prover constructs a ZKP proof demonstrating they know the private secret $s$ corresponding to public key $Y$ (using a non-interactive modular arithmetic **Schnorr Proof of Knowledge**).
   - Generates a Merkle membership path from the commitment $C$ to the public Merkle Root $R$ without revealing the leaf index or path to the ledger.
   - Computes a public **nullifier hash** $H_n = \text{SHA256}(n)$ to prevent double spending.
   - Binds the recipient's address to the challenge $e$ to prevent front-running/relay hijacking.

3. **Verification Phase (Withdrawal)**:
   - Verifies the Merkle membership path, validating that the commitment belongs to the pool.
   - Verifies the Schnorr signature mathematically ($g^z \equiv R_{schnorr} \cdot Y^e \pmod p$).
   - Verifies the nullifier hash is unused.
   - Releases the funds to the target recipient address.

4. **Security Sandbox**:
   - Simulated attack vectors: double spending, recipient tampering/front-running, invalid secret keys, and fake Merkle paths.
   - Observes verifier rejection logs in real-time.

5. **Visual UI**:
   - Premium dark-themed dashboard.
   - **Interactive Merkle Tree**: Visualizes SHA-256 tree hashing nodes with clickable path highlighting.

---

## 🛠️ Quick Start

### 1. Run the Server
The application runs on standard Python libraries with no external dependencies required.
```bash
python server.py
```
Open your browser and navigate to:
**[http://localhost:8000](http://localhost:8000)**

### 2. Run Automated Unit Tests
```bash
python test_zkp.py
```

---

## 📂 Project Structure
* `zkp.py` - Core cryptography (Merkle Tree, commitment scheme, Schnorr ZKP prover/verifier).
* `server.py` - Multithreaded HTTP API server and asset router.
* `index.html`, `style.css`, `app.js` - Visual dashboard and SVG tree renderer.
* `test_zkp.py` - 7 automated tests for cryptographic validation and attack security.
