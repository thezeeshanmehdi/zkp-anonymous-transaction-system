import unittest
import hashlib
from zkp import (
    MerkleTree,
    generate_deposit_credentials,
    generate_proof,
    verify_proof,
    verify_path,
    EMPTY_HASH,
    p, q, g
)

class TestTornadoZKPEngine(unittest.TestCase):
    def setUp(self):
        # Create a fresh tree of depth 4
        self.tree = MerkleTree(depth=4)
        self.spent_nullifiers = set()

    def test_merkle_tree_initialization(self):
        """Test tree correctly initializes with empty leaves and hashes them up to root."""
        root = self.tree.get_root()
        self.assertIsNotNone(root)
        self.assertEqual(len(root), 64) # SHA-256 hex string
        self.assertEqual(self.tree.leaves[0], EMPTY_HASH)
        self.assertEqual(len(self.tree.leaves), 16)

    def test_merkle_tree_insertion_and_path(self):
        """Test insertion of commitments and path correctness."""
        leaf_1 = hashlib.sha256(b"commitment_1").hexdigest()
        leaf_2 = hashlib.sha256(b"commitment_2").hexdigest()

        idx1 = self.tree.insert(leaf_1)
        idx2 = self.tree.insert(leaf_2)

        self.assertEqual(idx1, 0)
        self.assertEqual(idx2, 1)
        self.assertEqual(self.tree.leaves[0], leaf_1)
        self.assertEqual(self.tree.leaves[1], leaf_2)

        # Check path verification
        path_1 = self.tree.get_path(0)
        root = self.tree.get_root()
        self.assertTrue(verify_path(leaf_1, path_1, root))

        # Check incorrect leaf fails path verification
        self.assertFalse(verify_path(leaf_2, path_1, root))

    def test_successful_zkp_flow(self):
        """Test that a valid deposit can be successfully withdrawn using a valid proof."""
        s, n, Y, commitment = generate_deposit_credentials()
        idx = self.tree.insert(commitment)
        
        recipient = "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
        
        # Prover generates proof
        proof = generate_proof(s, n, recipient, self.tree, idx)
        
        # Verifier checks proof
        success, msg = verify_proof(proof, self.tree.get_root(), self.spent_nullifiers)
        self.assertTrue(success, f"Verification failed: {msg}")
        self.assertEqual(msg, "Proof successfully verified!")

    def test_double_spend_prevention(self):
        """Test that a nullifier cannot be used twice."""
        s, n, Y, commitment = generate_deposit_credentials()
        idx = self.tree.insert(commitment)
        
        recipient = "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
        
        # Generate proof
        proof = generate_proof(s, n, recipient, self.tree, idx)
        nullifier_hash = proof["public_inputs"]["nullifier_hash"]
        
        # First verification succeeds
        success, msg = verify_proof(proof, self.tree.get_root(), self.spent_nullifiers)
        self.assertTrue(success)
        
        # Register nullifier as spent
        self.spent_nullifiers.add(nullifier_hash)
        
        # Second verification fails
        success, msg = verify_proof(proof, self.tree.get_root(), self.spent_nullifiers)
        self.assertFalse(success)
        self.assertIn("Double spend", msg)

    def test_attack_tampered_recipient(self):
        """Test that changing the recipient address in the proof invalidates the signature."""
        s, n, Y, commitment = generate_deposit_credentials()
        idx = self.tree.insert(commitment)
        
        recipient = "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
        proof = generate_proof(s, n, recipient, self.tree, idx)
        
        # Attacker tampers with the recipient address in the public inputs
        proof["public_inputs"]["recipient"] = "0xATTACKER_ADDRESS_HERE"
        
        # Verification must fail because the challenge e binds the recipient address
        success, msg = verify_proof(proof, self.tree.get_root(), self.spent_nullifiers)
        self.assertFalse(success)
        self.assertIn("ownership verification failed", msg.lower())

    def test_attack_invalid_secret(self):
        """Test that attempting to withdraw with a wrong secret fails verification."""
        s, n, Y, commitment = generate_deposit_credentials()
        idx = self.tree.insert(commitment)
        
        recipient = "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
        proof = generate_proof(s, n, recipient, self.tree, idx)
        
        # Modify the public key Y associated with the Schnorr signature
        # to see if commitment matching or Schnorr signature checks fail.
        fake_s = s + "123"
        fake_Y_val = pow(g, int(fake_s, 16), p)
        proof["schnorr_proof"]["Y"] = hex(fake_Y_val)[2:]
        
        # Verify must fail since C = H(Y_fake || nullifier) will not match the commitment in the tree
        success, msg = verify_proof(proof, self.tree.get_root(), self.spent_nullifiers)
        self.assertFalse(success)
        self.assertIn("membership verification failed", msg.lower())

    def test_attack_fake_merkle_path(self):
        """Test that submitting a fake Merkle path fails verification."""
        s, n, Y, commitment = generate_deposit_credentials()
        idx = self.tree.insert(commitment)
        
        recipient = "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
        proof = generate_proof(s, n, recipient, self.tree, idx)
        
        # Tamper with path
        proof["merkle_witness"]["path"][0]["hash"] = "0" * 64
        
        success, msg = verify_proof(proof, self.tree.get_root(), self.spent_nullifiers)
        self.assertFalse(success)
        self.assertIn("membership verification failed", msg.lower())

if __name__ == "__main__":
    unittest.main()
