import http.server
import json
import os
import sys
import hashlib
from socketserver import ThreadingMixIn

class ThreadedHTTPServer(ThreadingMixIn, http.server.HTTPServer):
    """Handle requests in a separate thread."""
    daemon_threads = True
from zkp import (
    MerkleTree, 
    generate_deposit_credentials, 
    generate_proof, 
    verify_proof, 
    p, q, g, 
    EMPTY_HASH,
    hash_pair
)

PORT = 8000

# Server State
tree = MerkleTree(depth=4)
spent_nullifiers = set()
deposit_log = [] # Stores local wallet notes for frontend convenience

class TornadoServerHandler(http.server.BaseHTTPRequestHandler):
    def end_headers(self):
        # Allow CORS for development ease
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200, "ok")
        self.end_headers()

    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        if path == "/":
            self.serve_static_file("index.html", "text/html")
        elif path == "/index.html":
            self.serve_static_file("index.html", "text/html")
        elif path == "/style.css":
            self.serve_static_file("style.css", "text/css")
        elif path == "/app.js":
            self.serve_static_file("app.js", "application/javascript")
        elif path == "/api/state":
            self.send_json_response({
                "root": tree.get_root(),
                "leaves": tree.leaves,
                "spent_nullifiers": list(spent_nullifiers),
                "deposits": deposit_log,
                "empty_hash": EMPTY_HASH
            })
        else:
            self.send_error(404, "File Not Found")

    def do_POST(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        # Read request body
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = b""
        if content_length > 0:
            post_data = self.rfile.read(content_length)

        try:
            if path == "/api/deposit":
                # Create a deposit commitment
                s_hex, n_hex, Y_hex, commitment = generate_deposit_credentials()
                index = tree.insert(commitment)
                
                deposit_info = {
                    "index": index,
                    "secret": s_hex,
                    "nullifier": n_hex,
                    "Y": Y_hex,
                    "commitment": commitment
                }
                deposit_log.append(deposit_info)
                
                self.send_json_response({
                    "status": "success",
                    "deposit": deposit_info,
                    "root": tree.get_root()
                })

            elif path == "/api/generate-proof":
                data = json.loads(post_data.decode('utf-8'))
                secret = data.get("secret")
                nullifier = data.get("nullifier")
                index = int(data.get("index"))
                recipient = data.get("recipient")

                if not secret or not nullifier or index is None or not recipient:
                    self.send_json_response({"status": "error", "message": "Missing arguments"}, status=400)
                    return

                try:
                    proof = generate_proof(secret, nullifier, recipient, tree, index)
                    self.send_json_response({
                        "status": "success",
                        "proof": proof
                    })
                except Exception as e:
                    self.send_json_response({
                        "status": "error",
                        "message": f"Proof generation failed: {str(e)}"
                    }, status=400)

            elif path == "/api/verify-withdraw":
                data = json.loads(post_data.decode('utf-8'))
                proof = data.get("proof")

                if not proof:
                    self.send_json_response({"status": "error", "message": "Proof is missing"}, status=400)
                    return

                # Run verifier
                success, msg = verify_proof(proof, tree.get_root(), spent_nullifiers)
                if success:
                    # Register spent nullifier
                    nullifier_hash = proof["public_inputs"]["nullifier_hash"]
                    spent_nullifiers.add(nullifier_hash)
                    self.send_json_response({
                        "status": "success",
                        "message": "Withdrawal approved! ZKP verified successfully.",
                        "nullifier_hash": nullifier_hash
                    })
                else:
                    self.send_json_response({
                        "status": "error",
                        "message": f"ZKP verification failed: {msg}"
                    }, status=400)

            elif path == "/api/simulate-attack":
                data = json.loads(post_data.decode('utf-8'))
                attack_type = data.get("attack_type")
                index = int(data.get("index"))
                recipient = data.get("recipient")
                secret = data.get("secret")
                nullifier = data.get("nullifier")

                if attack_type == "double_spend":
                    # First generate a valid proof and withdraw
                    proof = generate_proof(secret, nullifier, recipient, tree, index)
                    
                    # Simulate double spend by checking against a temporary spent registry containing this nullifier
                    temp_spent = set(spent_nullifiers)
                    temp_spent.add(proof["public_inputs"]["nullifier_hash"])
                    
                    success, msg = verify_proof(proof, tree.get_root(), temp_spent)
                    self.send_json_response({
                        "status": "attack_result",
                        "attack_type": "double_spend",
                        "prevented": not success,
                        "message": msg
                    })

                elif attack_type == "tamper_recipient":
                    # Generate proof for 'recipient'
                    proof = generate_proof(secret, nullifier, recipient, tree, index)
                    # Change recipient in public inputs (mimicking a front-running attacker)
                    proof["public_inputs"]["recipient"] = "0xATTACKER_ADDRESS_9999"
                    
                    success, msg = verify_proof(proof, tree.get_root(), spent_nullifiers)
                    self.send_json_response({
                        "status": "attack_result",
                        "attack_type": "tamper_recipient",
                        "prevented": not success,
                        "message": msg
                    })

                elif attack_type == "invalid_secret":
                    # Prover generates proof with correct nullifier but fake secret
                    fake_secret = hex(int(secret, 16) + 12345)[2:]
                    
                    try:
                        # We try to craft a proof object manually with wrong secret to bypass Prover validation
                        # but check how Verifier rejects it
                        proof = generate_proof(secret, nullifier, recipient, tree, index)
                        # Tamper with the public key / Schnorr proof
                        # Compute Y for fake secret
                        fake_s_val = int(fake_secret, 16)
                        fake_Y_val = pow(g, fake_s_val, p)
                        proof["schnorr_proof"]["Y"] = hex(fake_Y_val)[2:]
                        
                        # Re-verify. The commitment C = H(Y_fake || nullifier) will fail the Merkle path check, 
                        # or the Schnorr signature will fail if the prover tries to sign for the real Y with fake secret
                        success, msg = verify_proof(proof, tree.get_root(), spent_nullifiers)
                        self.send_json_response({
                            "status": "attack_result",
                            "attack_type": "invalid_secret",
                            "prevented": not success,
                            "message": msg
                        })
                    except Exception as e:
                        self.send_json_response({
                            "status": "attack_result",
                            "attack_type": "invalid_secret",
                            "prevented": True,
                            "message": f"Proof generation crashed on invalid secret: {str(e)}"
                        })

                elif attack_type == "fake_merkle_path":
                    proof = generate_proof(secret, nullifier, recipient, tree, index)
                    # Tamper with Merkle path sibling hash
                    if len(proof["merkle_witness"]["path"]) > 0:
                        proof["merkle_witness"]["path"][0]["hash"] = "a" * 64
                    
                    success, msg = verify_proof(proof, tree.get_root(), spent_nullifiers)
                    self.send_json_response({
                        "status": "attack_result",
                        "attack_type": "fake_merkle_path",
                        "prevented": not success,
                        "message": msg
                    })

                else:
                    self.send_json_response({"status": "error", "message": "Unknown attack type"}, status=400)

            else:
                self.send_json_response({"status": "error", "message": "Endpoint not found"}, status=404)

        except Exception as e:
            self.send_json_response({
                "status": "error",
                "message": f"Server processing error: {str(e)}"
            }, status=500)

    def serve_static_file(self, filename, content_type):
        filepath = os.path.join(os.getcwd(), filename)
        if not os.path.exists(filepath):
            self.send_error(404, f"File {filename} not found")
            return
        
        try:
            with open(filepath, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        except Exception as e:
            self.send_error(500, f"Error reading file: {str(e)}")

    def send_json_response(self, data, status=200):
        try:
            response_bytes = json.dumps(data).encode('utf-8')
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response_bytes)))
            self.end_headers()
            self.wfile.write(response_bytes)
        except Exception as e:
            # Avoid infinite loop on failure
            print(f"Error sending JSON response: {e}")

# Helper import to avoid syntax issue in parse_url
import urllib.parse

def run(port=PORT):
    # Ensure current directory matches workspace
    workspace_dir = r"d:\BlockChain Quiz2"
    os.chdir(workspace_dir)
    server_address = ('', port)
    httpd = ThreadedHTTPServer(server_address, TornadoServerHandler)
    print(f"Tornado ZKP Simulation server running on http://localhost:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server...")
        httpd.server_close()
        sys.exit(0)

if __name__ == "__main__":
    run()
