import hashlib
import secrets
import json

# =====================================================================
# Cryptographic Parameters
# =====================================================================
# A 256-bit safe prime p = 2 * q + 1
# This ensures that modular exponentiation is cryptographically secure,
# and we can easily work with the prime-order subgroup of order q.
p = 220659860987613027372720785118499206888881941982648484855275083498906348014767
q = 110329930493806513686360392559249603444440970991324242427637541749453174007383

# Generator g (chosen as 4 = 2^2 mod p, which is a quadratic residue)
g = 4

# Sibling empty hash for leaf slots not yet filled
EMPTY_HASH = hashlib.sha256(b"empty_leaf_placeholder").hexdigest()


def hash_pair(a: str, b: str) -> str:
    """Concatenates and hashes two hex strings using SHA-256."""
    return hashlib.sha256((a + b).encode('utf-8')).hexdigest()


# =====================================================================
# Merkle Tree Implementation
# =====================================================================
class MerkleTree:
    def __init__(self, depth=4):
        self.depth = depth
        self.capacity = 2 ** depth
        self.leaves = [EMPTY_HASH] * self.capacity
        self.tree = [[] for _ in range(depth + 1)]
        self.rebuild()

    def rebuild(self):
        """Rebuilds the tree layers from the bottom leaves to the root."""
        self.tree[0] = list(self.leaves)
        for d in range(self.depth):
            level = []
            for i in range(0, len(self.tree[d]), 2):
                left = self.tree[d][i]
                right = self.tree[d][i+1]
                level.append(hash_pair(left, right))
            self.tree[d+1] = level

    def get_root(self) -> str:
        """Returns the current Merkle root."""
        return self.tree[self.depth][0]

    def insert(self, leaf_hash: str) -> int:
        """Inserts a leaf hash in the first available slot. Returns its index."""
        try:
            index = self.leaves.index(EMPTY_HASH)
        except ValueError:
            raise Exception("Merkle Tree is full! Mixing pool capacity reached.")
        
        self.leaves[index] = leaf_hash
        self.rebuild()
        return index

    def get_path(self, index: int) -> list:
        """Generates a Merkle membership proof (path) for a given leaf index."""
        if index < 0 or index >= self.capacity:
            raise Exception("Leaf index out of bounds")
        
        path = []
        curr_idx = index
        for d in range(self.depth):
            # Determine sibling index
            sibling_idx = curr_idx + 1 if curr_idx % 2 == 0 else curr_idx - 1
            sibling_hash = self.tree[d][sibling_idx]
            direction = 'left' if curr_idx % 2 == 1 else 'right'
            
            path.append({
                'hash': sibling_hash,
                'direction': direction
            })
            curr_idx = curr_idx // 2
        return path


def verify_path(leaf_hash: str, path: list, root: str) -> bool:
    """Verifies a Merkle path against a given leaf and root."""
    current = leaf_hash
    for step in path:
        sibling = step['hash']
        direction = step['direction']
        if direction == 'left':
            current = hash_pair(sibling, current)
        else:
            current = hash_pair(current, sibling)
    return current == root


# =====================================================================
# Commitment Scheme and ZKP Logic
# =====================================================================
def generate_deposit_credentials():
    """
    Generates a secret key s and a nullifier n.
    Computes public key Y = g^s mod p.
    Returns: (secret_s_hex, nullifier_n_hex, Y_hex, commitment)
    """
    # Generate cryptographically secure random integers
    s = secrets.randbelow(q - 1) + 1
    n_val = secrets.randbits(256)
    
    s_hex = hex(s)[2:]
    n_hex = hex(n_val)[2:]
    
    Y = pow(g, s, p)
    Y_hex = hex(Y)[2:]
    
    # Commitment: H(Y || n)
    commitment = hashlib.sha256((Y_hex + n_hex).encode('utf-8')).hexdigest()
    
    return s_hex, n_hex, Y_hex, commitment


def generate_proof(secret_s_hex: str, nullifier_n_hex: str, recipient_address: str, tree: MerkleTree, leaf_index: int):
    """
    Generates a zero-knowledge proof for a withdrawal.
    The proof demonstrates:
    1. Prover knows the secret 's' corresponding to public key Y = g^s mod p.
    2. Prover knows nullifier 'n' such that leaf C = H(Y || n) exists in the Merkle Tree.
    3. The proof is bound to the recipient address to prevent redirection/replay attacks.
    """
    s = int(secret_s_hex, 16)
    n = int(nullifier_n_hex, 16)
    
    Y = pow(g, s, p)
    Y_hex = hex(Y)[2:]
    
    # Compute commitment leaf and verify it matches what is in the tree
    commitment = hashlib.sha256((Y_hex + nullifier_n_hex).encode('utf-8')).hexdigest()
    if tree.leaves[leaf_index] != commitment:
        raise Exception("Provided credentials do not match the commitment at the specified index.")
    
    # Get Merkle path
    path = tree.get_path(leaf_index)
    root = tree.get_root()
    
    # Generate Schnorr Proof of Knowledge of 's'
    # 1. Prover chooses a random commitment nonce 'k'
    k = secrets.randbelow(q - 1) + 1
    R_schnorr = pow(g, k, p)
    
    # 2. Challenge e = H(g || Y || R_schnorr || Recipient) mod q
    e_input = f"{g}:{hex(Y)[2:]}:{hex(R_schnorr)[2:]}:{recipient_address}"
    e_hash = hashlib.sha256(e_input.encode('utf-8')).hexdigest()
    e = int(e_hash, 16) % q
    
    # 3. Response z = (k + e * s) mod q
    z = (k + e * s) % q
    
    # Nullifier Hash (published to prevent double spending): H_n = H(n)
    nullifier_hash = hashlib.sha256(nullifier_n_hex.encode('utf-8')).hexdigest()
    
    # ZKP Proof Structure (in a real ZKP, the witnesses are processed inside the cryptographic envelope)
    proof = {
        # Public Inputs
        "public_inputs": {
            "root": root,
            "nullifier_hash": nullifier_hash,
            "recipient": recipient_address
        },
        # Cryptographic elements
        "schnorr_proof": {
            "R_schnorr": hex(R_schnorr)[2:],
            "z": hex(z)[2:],
            "Y": Y_hex
        },
        # Merkle path (witness inside the ZKP envelope)
        "merkle_witness": {
            "path": path,
            "nullifier": nullifier_n_hex
        }
    }
    return proof


def verify_proof(proof: dict, root: str, spent_nullifiers: set) -> tuple:
    """
    Verifies the ZKP proof.
    Returns (True, "Success") or (False, "Error message")
    """
    try:
        public_inputs = proof["public_inputs"]
        schnorr = proof["schnorr_proof"]
        witness = proof["merkle_witness"]
        
        # 1. Check Merkle Root consistency
        if public_inputs["root"] != root:
            return False, "Proof root mismatch: The proof was generated for a different tree root."
        
        # 2. Check for double spend
        nullifier_hash = public_inputs["nullifier_hash"]
        if nullifier_hash in spent_nullifiers:
            return False, "Double spend attempt: This commitment nullifier has already been spent."
        
        # 3. Validate Nullifier Hash relation: SHA256(nullifier) == nullifier_hash
        nullifier = witness["nullifier"]
        expected_nullifier_hash = hashlib.sha256(nullifier.encode('utf-8')).hexdigest()
        if expected_nullifier_hash != nullifier_hash:
            return False, "Invalid proof: Nullifier does not match the public nullifier hash."
        
        # 4. Reconstruct commitment and verify Merkle membership proof
        Y_hex = schnorr["Y"]
        commitment = hashlib.sha256((Y_hex + nullifier).encode('utf-8')).hexdigest()
        
        path = witness["path"]
        if not verify_path(commitment, path, root):
            return False, "Invalid proof: Commitment membership verification failed in the Merkle Tree."
        
        # 5. Verify Schnorr Signature (Ownership Proof of 's')
        # Reconstruct public elements
        R_schnorr_val = int(schnorr["R_schnorr"], 16)
        z_val = int(schnorr["z"], 16)
        Y_val = int(Y_hex, 16)
        recipient = public_inputs["recipient"]
        
        # Validate values are in mathematical bounds
        if not (0 < R_schnorr_val < p) or not (0 < Y_val < p) or not (0 <= z_val < q):
            return False, "Invalid proof: Cryptographic elements are out of bounds."
            
        # Recompute challenge e
        e_input = f"{g}:{Y_hex}:{schnorr['R_schnorr']}:{recipient}"
        e_hash = hashlib.sha256(e_input.encode('utf-8')).hexdigest()
        e = int(e_hash, 16) % q
        
        # Check: g^z == R_schnorr * Y^e (mod p)
        lhs = pow(g, z_val, p)
        rhs = (R_schnorr_val * pow(Y_val, e, p)) % p
        
        if lhs != rhs:
            return False, "Invalid proof: Ownership verification failed. Schnorr proof is mathematically invalid."
            
        return True, "Proof successfully verified!"
        
    except Exception as e:
        return False, f"Proof verification error: {str(e)}"
