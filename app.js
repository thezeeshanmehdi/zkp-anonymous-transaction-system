// =====================================================================
// App State and Config
// =====================================================================
let appState = {
    root: "",
    leaves: [],
    spentNullifiers: [],
    sessionDeposits: [], // Wallet notes generated locally
    emptyHash: "",
    activePathLeafIndex: null // Currently highlighted leaf in Merkle tab
};

const API_BASE = ""; // Same origin

// =====================================================================
// Initialization
// =====================================================================
document.addEventListener("DOMContentLoaded", () => {
    initTabs();
    initCopyButtons();
    loadSessionWallet();
    fetchState().then(() => {
        renderPool();
        renderMerkleTree();
        updateSandboxDropdown();
    });

    // Event Listeners
    document.getElementById("btn-deposit").addEventListener("click", handleDeposit);
    document.getElementById("btn-withdraw").addEventListener("click", handleWithdraw);
    
    // Attack buttons
    document.querySelectorAll(".run-attack-btn").forEach(btn => {
        btn.addEventListener("click", (e) => {
            const attackType = e.currentTarget.getAttribute("data-attack");
            runAttack(attackType);
        });
    });
});

// =====================================================================
// Tab Navigation
// =====================================================================
function initTabs() {
    const navButtons = document.querySelectorAll(".nav-btn");
    const tabContents = document.querySelectorAll(".tab-content");

    navButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            const tabId = btn.getAttribute("data-tab");
            
            navButtons.forEach(b => b.classList.remove("active"));
            tabContents.forEach(tc => tc.classList.remove("active"));
            
            btn.classList.add("active");
            document.getElementById(`tab-${tabId}`).classList.add("active");

            if (tabId === "merkle") {
                // Trigger Merkle Tree render on resize/tab change to ensure correct SVG scaling
                setTimeout(renderMerkleTree, 50);
            }
        });
    });
}

// =====================================================================
// Copy to Clipboard Helpers
// =====================================================================
function initCopyButtons() {
    document.addEventListener("click", (e) => {
        const copyBtn = e.target.closest(".copy-btn");
        if (!copyBtn) return;
        
        const targetId = copyBtn.getAttribute("data-target");
        const element = document.getElementById(targetId);
        if (!element) return;
        
        const textToCopy = element.innerText;
        navigator.clipboard.writeText(textToCopy).then(() => {
            const originalHTML = copyBtn.innerHTML;
            copyBtn.innerHTML = '<i class="fa-solid fa-check text-cyan"></i>';
            setTimeout(() => {
                copyBtn.innerHTML = originalHTML;
            }, 1500);
        }).catch(err => {
            console.error("Failed to copy text: ", err);
        });
    });
}

// =====================================================================
// State Sync with API
// =====================================================================
async function fetchState() {
    try {
        const response = await fetch(`${API_BASE}/api/state`);
        if (!response.ok) throw new Error("Failed to fetch state");
        const data = await response.json();
        
        appState.root = data.root;
        appState.leaves = data.leaves;
        appState.spentNullifiers = data.spent_nullifiers;
        appState.emptyHash = data.empty_hash;
        
        // Update top metrics bar
        document.getElementById("metric-root").innerText = data.root;
        document.getElementById("metric-root").title = data.root;
        
        const activeCount = data.leaves.filter(h => h !== data.empty_hash).length;
        document.getElementById("metric-deposits").innerText = `${activeCount} / 16`;
        document.getElementById("metric-nullifiers").innerText = data.spent_nullifiers.length;
        
    } catch (err) {
        console.error("Error fetching state:", err);
    }
}

// =====================================================================
// Wallet / Note Management
// =====================================================================
function loadSessionWallet() {
    const stored = localStorage.getItem("aeroshield_wallet");
    if (stored) {
        try {
            appState.sessionDeposits = jsonParseLargeInt(stored);
            renderWalletNotes();
        } catch (e) {
            console.error("Error parsing wallet localStorage:", e);
            appState.sessionDeposits = [];
        }
    }
}

function saveSessionWallet() {
    localStorage.setItem("aeroshield_wallet", JSON.stringify(appState.sessionDeposits));
}

// Helper to handle potential large int issues in JSON stringify/parse
function jsonParseLargeInt(str) {
    return JSON.parse(str);
}

function renderWalletNotes() {
    const container = document.getElementById("notes-list");
    container.innerHTML = "";
    
    if (appState.sessionDeposits.length === 0) {
        container.innerHTML = `<div class="empty-placeholder">No deposits made in this session yet. Click Deposit above to start.</div>`;
        return;
    }
    
    // Sort deposits descending
    const sorted = [...appState.sessionDeposits].reverse();
    
    sorted.forEach(d => {
        // Find if this leaf is spent
        const nullifierHash = d.nullifier_hash || sha256(d.nullifier);
        const isSpent = appState.spentNullifiers.includes(nullifierHash);
        
        const noteItem = document.createElement("div");
        noteItem.className = `note-item ${isSpent ? 'spent' : ''}`;
        
        noteItem.innerHTML = `
            <div class="note-meta">
                <span class="note-idx">Leaf #${d.index} ${isSpent ? '(SPENT)' : '(ACTIVE)'}</span>
                <span class="note-hash code-font">Commitment: ${d.commitment.substring(0, 10)}...${d.commitment.substring(58)}</span>
            </div>
            <div class="note-actions">
                <button class="use-note-btn" onclick="populateWithdrawForm(${d.index}, '${d.secret}', '${d.nullifier}')">
                    <i class="fa-solid fa-file-import"></i> Use Note
                </button>
            </div>
        `;
        container.appendChild(noteItem);
    });
}

window.populateWithdrawForm = function(index, secret, nullifier) {
    document.getElementById("withdraw-index").value = index;
    document.getElementById("withdraw-secret").value = secret;
    document.getElementById("withdraw-nullifier").value = nullifier;
    
    // Scroll and highlight form elements
    document.getElementById("withdraw-form").scrollIntoView({ behavior: "smooth" });
    logZkp("Prover console", `Auto-populated credentials from note #${index}. Click 'Withdraw' to compute verification proofs.`, "system");
};

// =====================================================================
// Deposit Flow
// =====================================================================
async function handleDeposit() {
    const btn = document.getElementById("btn-deposit");
    const resultBox = document.getElementById("deposit-result-box");
    
    btn.disabled = true;
    btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Submitting Commitment...`;
    
    try {
        const response = await fetch(`${API_BASE}/api/deposit`, { method: "POST" });
        if (!response.ok) throw new Error("Deposit request failed");
        
        const resData = await response.json();
        
        if (resData.status === "success") {
            const dep = resData.deposit;
            
            // Generate nullifier hash to store locally
            const nHash = sha256(dep.nullifier);
            
            // Save to local session deposits
            appState.sessionDeposits.push({
                index: dep.index,
                secret: dep.secret,
                nullifier: dep.nullifier,
                Y: dep.Y,
                commitment: dep.commitment,
                nullifier_hash: nHash
            });
            saveSessionWallet();
            
            // Update inputs and show credentials card
            document.getElementById("res-index").innerText = `#${dep.index}`;
            document.getElementById("res-secret").innerText = dep.secret;
            document.getElementById("res-nullifier").innerText = dep.nullifier;
            document.getElementById("res-commitment").innerText = dep.commitment;
            resultBox.classList.remove("hidden");
            
            // Sync state and redraw
            await fetchState();
            renderPool();
            renderMerkleTree();
            renderWalletNotes();
            updateSandboxDropdown();
            
            // Visual alert
            logZkp("Mixer console", `[Deposit Success] Commitment leaf registered at index ${dep.index}.`, "success");
        } else {
            alert(`Deposit failed: ${resData.message}`);
        }
    } catch (err) {
        console.error(err);
        alert(`Network Error: ${err.message}`);
    } finally {
        btn.disabled = false;
        btn.innerHTML = `<i class="fa-solid fa-coins"></i> Deposit 1.0 TORN`;
    }
}

// =====================================================================
// Withdrawal & ZKP Verification Flow
// =====================================================================
async function handleWithdraw() {
    const btn = document.getElementById("btn-withdraw");
    const consolePanel = document.getElementById("zkp-log-panel");
    const consoleBox = document.getElementById("zkp-console");
    
    const index = document.getElementById("withdraw-index").value;
    const secret = document.getElementById("withdraw-secret").value.trim();
    const nullifier = document.getElementById("withdraw-nullifier").value.trim();
    const recipient = document.getElementById("withdraw-recipient").value.trim();

    if (!index || !secret || !nullifier || !recipient) {
        alert("Please fill in all withdrawal fields.");
        return;
    }

    btn.disabled = true;
    btn.innerHTML = `<i class="fa-solid fa-gears fa-spin"></i> Processing ZKP...`;
    
    // Clear and open console panel
    consoleBox.innerHTML = "";
    consolePanel.classList.remove("hidden");
    
    logZkp("withdraw", "Initializing Prover...", "system");
    logZkp("withdraw", `Generating witnesses from input... s: ${secret.substring(0, 8)}..., n: ${nullifier.substring(0, 8)}...`, "prover");
    
    try {
        // Step 1: Request ZKP Proof generation from local wallet/prover backend
        logZkp("withdraw", "Calculating Merkle Membership Path and public key Y = g^s mod p...", "prover");
        const proofRes = await fetch(`${API_BASE}/api/generate-proof`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ secret, nullifier, index, recipient })
        });
        
        if (!proofRes.ok) {
            const errorData = await proofRes.json();
            throw new Error(errorData.message || "Proof generation failed");
        }
        
        const proofData = await proofRes.json();
        const proof = proofData.proof;
        
        logZkp("withdraw", `[ZKP Prover] Proof generated successfully!`, "success");
        logZkp("withdraw", `Public Root: ${proof.public_inputs.root}`, "prover");
        logZkp("withdraw", `Nullifier Hash: ${proof.public_inputs.nullifier_hash}`, "prover");
        logZkp("withdraw", `Schnorr Proof values: R = ${proof.schnorr_proof.R_schnorr.substring(0, 10)}..., z = ${proof.schnorr_proof.z.substring(0, 10)}...`, "prover");
        logZkp("withdraw", `Submitting proof to AeroShield Verifier Smart Contract...`, "system");
        
        // Step 2: Submit proof payload to the verifier
        const verifyRes = await fetch(`${API_BASE}/api/verify-withdraw`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ proof })
        });
        
        const verifyData = await verifyRes.json();
        
        if (verifyRes.ok && verifyData.status === "success") {
            logZkp("withdraw", `[Verifier Contract] Root matches stored ledger state. Check passed.`, "verifier");
            logZkp("withdraw", `[Verifier Contract] Nullifier check: ${proof.public_inputs.nullifier_hash} is unused. Check passed.`, "verifier");
            logZkp("withdraw", `[Verifier Contract] Reciprocal commitment reconstruction C = H(Y || nullifier) match in Merkle proof. Check passed.`, "verifier");
            logZkp("withdraw", `[Verifier Contract] Verifying Schnorr discrete logarithm ownership: g^z == R_schnorr * Y^e (mod p)... Check passed.`, "verifier");
            logZkp("withdraw", `[Verifier Contract] ${verifyData.message}`, "success");
            logZkp("withdraw", `Released 1.0 TORN to recipient: ${recipient}`, "success");
            
            // Highlight path in tree
            appState.activePathLeafIndex = parseInt(index);
            
            // Sync states
            await fetchState();
            renderPool();
            renderMerkleTree();
            renderWalletNotes();
        } else {
            logZkp("withdraw", `[Verifier Contract Rejection] ${verifyData.message}`, "error");
        }
        
    } catch (err) {
        logZkp("withdraw", `Error: ${err.message}`, "error");
    } finally {
        btn.disabled = false;
        btn.innerHTML = `<i class="fa-solid fa-shield-halved"></i> Generate Proof & Withdraw`;
    }
}

// =====================================================================
// Attack Sandbox Execution
// =====================================================================
async function runAttack(attackType) {
    const targetIdx = document.getElementById("sandbox-deposit-select").value;
    const consoleBox = document.getElementById("sandbox-console");
    
    if (targetIdx === "") {
        alert("Please select a target deposit from the dropdown. If the pool is empty, perform a deposit first.");
        return;
    }
    
    // Find deposit details locally
    const deposit = appState.sessionDeposits.find(d => d.index == targetIdx);
    if (!deposit) {
        alert("Selected deposit credentials not found in local browser state.");
        return;
    }

    consoleBox.innerHTML = "";
    logSandbox(`[Sandbox] Simulating ${attackType.replace('_', ' ')} attack targetting Leaf Node #${targetIdx}...`, "system");
    logSandbox(`Target commitment: ${deposit.commitment}`, "system");
    
    try {
        const response = await fetch(`${API_BASE}/api/simulate-attack`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                attack_type: attackType,
                index: deposit.index,
                secret: deposit.secret,
                nullifier: deposit.nullifier,
                recipient: "0x3f5CE4E5a3D23f001A837A3aE75c40De32A2d7aB"
            })
        });
        
        const data = await response.json();
        
        if (data.status === "attack_result") {
            if (data.prevented) {
                logSandbox(`[Attack Prevented] The verifier safely rejected the transaction payload.`, "success");
                logSandbox(`Verifier Rejection Code: "${data.message}"`, "error");
                logSandbox(`Result: Attack failed. Zero-Knowledge rules enforced.`, "success");
            } else {
                logSandbox(`[Attack Succeeded] WARNING: Security breach occurred! Reason: ${data.message}`, "error");
            }
        } else {
            logSandbox(`Error from server: ${data.message}`, "error");
        }
        
        // Sync states to reflect any double spends or spent registries
        await fetchState();
        renderPool();
        renderWalletNotes();
        
    } catch (err) {
        logSandbox(`Connection error during attack execution: ${err.message}`, "error");
    }
}

// =====================================================================
// Log Helpers
// =====================================================================
function logZkp(action, message, type = "system") {
    const consoleBox = document.getElementById("zkp-console");
    if (!consoleBox) return;
    
    const line = document.createElement("div");
    line.className = `console-line ${type}`;
    
    let prefix = "[System]";
    if (type === "prover") prefix = "[ZKP Prover]";
    if (type === "verifier") prefix = "[ZKP Verifier]";
    if (type === "success") prefix = "[Success]";
    if (type === "error") prefix = "[Rejected]";
    
    line.innerText = `${prefix} ${message}`;
    consoleBox.appendChild(line);
    consoleBox.scrollTop = consoleBox.scrollHeight;
}

function logSandbox(message, type = "system") {
    const consoleBox = document.getElementById("sandbox-console");
    if (!consoleBox) return;
    
    const line = document.createElement("div");
    line.className = `console-line ${type}`;
    line.innerText = message;
    consoleBox.appendChild(line);
    consoleBox.scrollTop = consoleBox.scrollHeight;
}

// =====================================================================
// UI Render Helpers
// =====================================================================
function renderPool() {
    const container = document.getElementById("commitments-pool");
    container.innerHTML = "";
    
    appState.leaves.forEach((leaf, idx) => {
        const isEmpty = leaf === appState.emptyHash;
        const nHash = appState.sessionDeposits.find(d => d.index === idx)?.nullifier_hash || "";
        const isSpent = nHash && appState.spentNullifiers.includes(nHash);
        
        const node = document.createElement("div");
        node.className = `pool-node ${isEmpty ? '' : 'active-node'} ${isSpent ? 'spent-node' : ''}`;
        
        let statusBadge = `<span class="node-badge badge-empty">Empty</span>`;
        if (!isEmpty) {
            statusBadge = isSpent 
                ? `<span class="node-badge badge-spent">Spent</span>`
                : `<span class="node-badge badge-active">Deposited</span>`;
        }
        
        node.innerHTML = `
            <div class="node-header">
                <span class="node-idx-label">NODE #${idx}</span>
                ${statusBadge}
            </div>
            <div class="node-hash-value code-font">
                ${isEmpty ? '0x0000000000000000...' : `${leaf.substring(0, 10)}...${leaf.substring(54)}`}
            </div>
        `;
        
        // Setup click to fill withdraw form if node is populated and active
        if (!isEmpty && !isSpent) {
            node.style.cursor = "pointer";
            node.title = "Click to load note into withdraw form";
            node.addEventListener("click", () => {
                const dep = appState.sessionDeposits.find(d => d.index === idx);
                if (dep) {
                    populateWithdrawForm(dep.index, dep.secret, dep.nullifier);
                } else {
                    // Node deposited by another user or session, we don't have credentials
                    document.getElementById("withdraw-index").value = idx;
                    document.getElementById("withdraw-secret").value = "";
                    document.getElementById("withdraw-nullifier").value = "";
                    logZkp("Prover console", `Selected Leaf Node #${idx}. Note: Credentials for this deposit are not stored in your local wallet session. Enter them manually to generate proofs.`, "system");
                }
            });
        }
        
        container.appendChild(node);
    });
}

function updateSandboxDropdown() {
    const select = document.getElementById("sandbox-deposit-select");
    select.innerHTML = "";
    
    // Select index that are active (deposited but not spent)
    const activeDeposits = appState.sessionDeposits.filter(d => {
        const isSpent = appState.spentNullifiers.includes(d.nullifier_hash);
        return !isSpent;
    });
    
    if (activeDeposits.length === 0) {
        select.innerHTML = `<option value="">-- No active session deposits available --</option>`;
        return;
    }
    
    activeDeposits.forEach(d => {
        const option = document.createElement("option");
        option.value = d.index;
        option.innerText = `Leaf #${d.index} (Commitment: ${d.commitment.substring(0, 8)}...)`;
        select.appendChild(option);
    });
}

// =====================================================================
// Merkle Tree SVG Rendering
// =====================================================================
function renderMerkleTree() {
    const svg = document.getElementById("merkle-svg");
    if (!svg) return;
    
    // Clear previous SVG content
    svg.innerHTML = "";
    
    const svgWidth = svg.clientWidth || 800;
    const svgHeight = 450;
    const depth = 4;
    
    // Layout parameters
    const marginTop = 50;
    const levelSpacing = 80;
    
    // Calculate node coordinates in hierarchical tree
    // levels will hold nodes at level 0 (leaves) up to level 4 (root)
    let nodeCoordinates = {}; // Key: "L_I" -> {x, y, hash, is_empty}
    
    // Build tree hashes
    let treeHashes = Array.from({ length: depth + 1 }, () => []);
    treeHashes[0] = [...appState.leaves];
    
    // Compute internal hashes locally for representation
    for (let d = 0; d < depth; d++) {
        let level = [];
        for (let i = 0; i < treeHashes[d].length; i += 2) {
            let left = treeHashes[d][i];
            let right = treeHashes[d][i+1];
            level.push(hashPair(left, right));
        }
        treeHashes[d+1] = level;
    }
    
    // Draw links first (underneath circles)
    for (let d = 0; d < depth; d++) {
        const currentLevelNodes = 1 << (depth - d); // 2^(4-d)
        const parentLevelNodes = 1 << (depth - (d + 1));
        
        for (let i = 0; i < currentLevelNodes; i++) {
            const childX = getXCoord(d, i, svgWidth);
            const childY = getYCoord(d, depth, marginTop, levelSpacing);
            
            const parentIdx = Math.floor(i / 2);
            const parentX = getXCoord(d + 1, parentIdx, svgWidth);
            const parentY = getYCoord(d + 1, depth, marginTop, levelSpacing);
            
            // Check if active path links
            let isActiveLink = false;
            if (appState.activePathLeafIndex !== null) {
                const pathIdxAtLevel = Math.floor(appState.activePathLeafIndex / (1 << d));
                const parentPathIdx = Math.floor(appState.activePathLeafIndex / (1 << (d + 1)));
                if (i === pathIdxAtLevel && parentIdx === parentPathIdx) {
                    isActiveLink = true;
                }
            }
            
            const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
            line.setAttribute("x1", childX);
            line.setAttribute("y1", childY);
            line.setAttribute("x2", parentX);
            line.setAttribute("y2", parentY);
            line.setAttribute("class", `tree-link ${isActiveLink ? 'active-link' : ''}`);
            svg.appendChild(line);
        }
    }
    
    // Draw nodes
    for (let d = 0; d <= depth; d++) {
        const numNodes = 1 << (depth - d);
        for (let i = 0; i < numNodes; i++) {
            const x = getXCoord(d, i, svgWidth);
            const y = getYCoord(d, depth, marginTop, levelSpacing);
            const hash = treeHashes[d][i] || appState.emptyHash;
            const isEmpty = hash === appState.emptyHash;
            const isRoot = d === depth;
            
            let isActive = false;
            if (appState.activePathLeafIndex !== null) {
                const pathIdxAtLevel = Math.floor(appState.activePathLeafIndex / (1 << d));
                if (i === pathIdxAtLevel) {
                    isActive = true;
                }
            }
            
            // Node circle
            const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
            circle.setAttribute("cx", x);
            circle.setAttribute("cy", y);
            circle.setAttribute("r", isRoot ? 14 : (d === 0 ? 10 : 8));
            
            let classList = "tree-node-circle";
            if (isEmpty) classList += " empty";
            if (isRoot) classList += " root";
            if (isActive) classList += " active";
            circle.setAttribute("class", classList);
            
            // Click listener for leaves to show Merkle path details
            if (d === 0) {
                circle.setAttribute("style", "cursor: pointer");
                circle.addEventListener("click", () => {
                    appState.activePathLeafIndex = i;
                    renderMerkleTree();
                    showMerklePathDetails(i);
                });
            }
            
            svg.appendChild(circle);
            
            // Labels for levels (only print Index/Labels on key nodes to avoid clutter)
            if (d === 0 || isRoot) {
                const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
                text.setAttribute("x", x);
                text.setAttribute("y", y + (d === 0 ? 22 : -20));
                text.setAttribute("text-anchor", "middle");
                text.setAttribute("class", "tree-label");
                text.textContent = isRoot ? "ROOT" : `#${i}`;
                svg.appendChild(text);
            }
        }
    }
}

function getXCoord(level, index, svgWidth) {
    const numNodes = 1 << (4 - level); // 2^(4-L)
    const segment = svgWidth / numNodes;
    return segment * index + (segment / 2);
}

function getYCoord(level, depth, marginTop, levelSpacing) {
    return marginTop + (depth - level) * levelSpacing;
}

// Helper local array functions
function range(size) {
    return [...Array(size).keys()];
}

// Simple local hash pairing helper mimicking python hash_pair
function hashPair(a, b) {
    // Basic local SHA-256 for Javascript tree rendering representation
    return sha256(a + b);
}

// JS SHA256 helper
function sha256(ascii) {
    function rotateRight(n,x) {
        return ((n>>>x) | (n<<(32-x)));
    }
    function choice(x,y,z) { return ((x & y) ^ (~x & z)); }
    function majority(x,y,z) { return ((x & y) ^ (x & z) ^ (y & z)); }
    
    let k = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];
    
    let hash = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    
    let words = [];
    let asciiLength = ascii.length;
    for (let i = 0; i < asciiLength; i++) {
        words[i >>> 2] |= (ascii.charCodeAt(i) & 0xff) << (24 - ((i & 3) << 3));
    }
    
    let bitsLength = asciiLength * 8;
    words[bitsLength >>> 5] |= 0x80 << (24 - (bitsLength & 31));
    words[(((bitsLength + 64) >>> 9) << 4) + 15] = bitsLength;
    
    let w = [];
    for (let i = 0; i < words.length; i += 16) {
        let a = hash[0], b = hash[1], c = hash[2], d = hash[3], e = hash[4], f = hash[5], g = hash[6], h = hash[7];
        
        for (let j = 0; j < 64; j++) {
            if (j < 16) {
                w[j] = words[i + j] | 0;
            } else {
                let s0 = rotateRight(w[j - 15], 7) ^ rotateRight(w[j - 15], 18) ^ (w[j - 15] >>> 3);
                let s1 = rotateRight(w[j - 2], 17) ^ rotateRight(w[j - 2], 19) ^ (w[j - 2] >>> 10);
                w[j] = (w[j - 16] + s0 + w[j - 7] + s1) | 0;
            }
            
            let temp1 = (h + (rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25)) + choice(e, f, g) + k[j] + w[j]) | 0;
            let temp2 = ((rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22)) + majority(a, b, c)) | 0;
            
            h = g;
            g = f;
            f = e;
            e = (d + temp1) | 0;
            d = c;
            c = b;
            b = a;
            a = (temp1 + temp2) | 0;
        }
        
        hash[0] = (hash[0] + a) | 0;
        hash[1] = (hash[1] + b) | 0;
        hash[2] = (hash[2] + c) | 0;
        hash[3] = (hash[3] + d) | 0;
        hash[4] = (hash[4] + e) | 0;
        hash[5] = (hash[5] + f) | 0;
        hash[6] = (hash[6] + g) | 0;
        hash[7] = (hash[7] + h) | 0;
    }
    
    let result = "";
    for (let i = 0; i < 8; i++) {
        let hex = (hash[i] >>> 0).toString(16);
        result += "00000000".substring(hex.length) + hex;
    }
    return result;
}

// =====================================================================
// Merkle Path Details Display
// =====================================================================
function showMerklePathDetails(leafIdx) {
    const detailsBox = document.getElementById("path-details-box");
    const stepsList = document.getElementById("path-steps-list");
    document.getElementById("path-leaf-idx").innerText = `#${leafIdx}`;
    
    detailsBox.classList.remove("hidden");
    stepsList.innerHTML = "";
    
    let currentHash = appState.leaves[leafIdx];
    
    // Simulate path generation locally to show visual step-by-step math
    let currentIdx = leafIdx;
    const depth = 4;
    
    // Build tree hashes
    let treeHashes = Array.from({ length: depth + 1 }, () => []);
    treeHashes[0] = [...appState.leaves];
    for (let d = 0; d < depth; d++) {
        let level = [];
        for (let i = 0; i < treeHashes[d].length; i += 2) {
            level.push(hashPair(treeHashes[d][i], treeHashes[d][i+1]));
        }
        treeHashes[d+1] = level;
    }
    
    for (let d = 0; d < depth; d++) {
        const siblingIdx = currentIdx % 2 === 0 ? currentIdx + 1 : currentIdx - 1;
        const siblingHash = treeHashes[d][siblingIdx] || appState.emptyHash;
        const direction = currentIdx % 2 === 1 ? 'left' : 'right';
        
        let nextHash = "";
        let mathText = "";
        if (direction === 'left') {
            nextHash = hashPair(siblingHash, currentHash);
            mathText = `SHA256(Sibling [${siblingHash.substring(0,6)}...] + Node [${currentHash.substring(0,6)}...])`;
        } else {
            nextHash = hashPair(currentHash, siblingHash);
            mathText = `SHA256(Node [${currentHash.substring(0,6)}...] + Sibling [${siblingHash.substring(0,6)}...])`;
        }
        
        const stepRow = document.createElement("div");
        stepRow.className = "path-step-item";
        stepRow.innerHTML = `
            <span class="step-meta">Level ${d} &rarr; ${d+1} (${direction === 'left' ? 'Sibling is Left' : 'Sibling is Right'})</span>
            <span class="code-font text-secondary" style="font-size:0.7rem; max-width: 400px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${mathText}">${mathText}</span>
            <div class="step-hashes">
                <span class="code-font text-cyan" title="New Node Hash">${nextHash.substring(0,8)}...</span>
            </div>
        `;
        stepsList.appendChild(stepRow);
        
        currentHash = nextHash;
        currentIdx = Math.floor(currentIdx / 2);
    }
}
