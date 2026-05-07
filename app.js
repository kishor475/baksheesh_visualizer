const SBox = [3, 0, 6, 13, 11, 5, 8, 14, 12, 15, 9, 2, 4, 10, 7, 1];
const SBoxInv = new Array(16);
SBox.forEach((v, i) => { SBoxInv[v] = i; });

const Perm = [
    0, 33, 66, 99, 96, 1, 34, 67, 64, 97, 2, 35, 32, 65, 98, 3, 4, 37, 70, 103,
    100, 5, 38, 71, 68, 101, 6, 39, 36, 69, 102, 7, 8, 41, 74, 107, 104, 9, 42, 75,
    72, 105, 10, 43, 40, 73, 106, 11, 12, 45, 78, 111, 108, 13, 46, 79, 76, 109, 14, 47,
    44, 77, 110, 15, 16, 49, 82, 115, 112, 17, 50, 83, 80, 113, 18, 51, 48, 81, 114, 19,
    20, 53, 86, 119, 116, 21, 54, 87, 84, 117, 22, 55, 52, 85, 118, 23, 24, 57, 90, 123,
    120, 25, 58, 91, 88, 121, 26, 59, 56, 89, 122, 27, 28, 61, 94, 127, 124, 29, 62, 95,
    92, 125, 30, 63, 60, 93, 126, 31
];

// inverse permutation table
const PermInv = new Array(128);
Perm.forEach((dest, src) => { PermInv[dest] = src; });

const Constants = [2, 33, 16, 9, 36, 19, 40, 53, 26, 13, 38, 51, 56, 61, 62, 31, 14, 7, 34,
    49, 24, 45, 54, 59, 28, 47, 22, 43, 20, 11, 4, 3, 32, 17, 8];
const Taps = [8, 13, 19, 35, 67, 106];

function hexToBits(hex) {
    let bits = [];
    for (let i = 0; i < hex.length; i++) {
        let val = parseInt(hex[i], 16);
        bits.push((val >> 3) & 1);
        bits.push((val >> 2) & 1);
        bits.push((val >> 1) & 1);
        bits.push(val & 1);
    }
    return bits.reverse();
}

function bitsToNibbles(bits) {
    let nibbles = [];
    for (let i = 127; i >= 0; i -= 4) {
        let val = (bits[i] << 3) | (bits[i - 1] << 2) | (bits[i - 2] << 1) | bits[i - 3];
        nibbles.push(val.toString(16).toUpperCase());
    }
    return nibbles;
}

function applySBox(state, box) {
    for (let i = 0; i < 32; i++) {
        let off = i * 4;
        let val = (state[off + 3] << 3) | (state[off + 2] << 2) | (state[off + 1] << 1) | state[off];
        let sub = box[val];
        state[off] = sub & 1;
        state[off + 1] = (sub >> 1) & 1;
        state[off + 2] = (sub >> 2) & 1;
        state[off + 3] = (sub >> 3) & 1;
    }
}

function applyPerm(state, table) {
    let next = Array(128).fill(0);
    for (let i = 0; i < 128; i++) next[table[i]] = state[i];
    return next;
}

function applyConstants(state, roundIndex) {
    let c = Constants[roundIndex];
    for (let i = 0; i < 6; i++) state[Taps[i]] ^= ((c >> i) & 1);
}

function rotateKeyRight(key) {
    let next = Array(128).fill(0);
    let bit0 = key[0];
    for (let i = 0; i < 127; i++) next[i] = key[i + 1];
    next[127] = bit0;
    return next;
}

function rotateKeyLeft(key) {
    let next = Array(128).fill(0);
    let bit127 = key[127];
    for (let i = 127; i > 0; i--) next[i] = key[i - 1];
    next[0] = bit127;
    return next;
}

function generateEncryptTrace(ptHex, keyHex) {
    let trace = [];
    let state = hexToBits(ptHex);
    let key = hexToBits(keyHex);

    trace.push({ round: 0, op: "Plaintext Loaded", class: "", nibbles: bitsToNibbles(state), keyNibbles: null });

    // whitening key
    for (let i = 0; i < 128; i++) state[i] ^= key[i];
    trace.push({ round: 0, op: "Initial Key XOR (Whitening)", class: "op-AddRoundKey", nibbles: bitsToNibbles(state), keyNibbles: bitsToNibbles(key) });

    for (let r = 1; r <= 35; r++) {
        applySBox(state, SBox);
        trace.push({ round: r, op: "SubCells", class: "op-SubCells", nibbles: bitsToNibbles(state), keyNibbles: null });

        state = applyPerm(state, Perm);
        trace.push({ round: r, op: "PermBits", class: "op-PermBits", nibbles: bitsToNibbles(state), keyNibbles: null });

        applyConstants(state, r - 1);
        trace.push({ round: r, op: "AddConstants", class: "op-AddConstants", nibbles: bitsToNibbles(state), keyNibbles: null });

        // Advance key then XOR
        key = rotateKeyRight(key);
        for (let i = 0; i < 128; i++) state[i] ^= key[i];
        trace.push({ round: r, op: "AddRoundKey", class: "op-AddRoundKey", nibbles: bitsToNibbles(state), keyNibbles: bitsToNibbles(key) });
    }

    trace.push({ round: 35, op: "Ciphertext Generated", class: "", nibbles: bitsToNibbles(state), keyNibbles: null });
    return trace;
}

function generateDecryptTrace(ctHex, keyHex) {
    let trace = [];
    let state = hexToBits(ctHex);

    // precomputing all 36 round keys (K0 … K35)
    let keys = [];
    let key = hexToBits(keyHex);
    keys.push(key.slice());
    for (let r = 1; r <= 35; r++) {
        key = rotateKeyRight(key);
        keys.push(key.slice());
    }

    trace.push({ round: 35, op: "Ciphertext Loaded", class: "", nibbles: bitsToNibbles(state), keyNibbles: null });

    // Reverse round 35 down to round 1
    for (let r = 35; r >= 1; r--) {
        // undo AddRoundKey 
        for (let i = 0; i < 128; i++) state[i] ^= keys[r][i];
        trace.push({ round: r, op: "AddRoundKey (Inv)", class: "op-AddRoundKey", nibbles: bitsToNibbles(state), keyNibbles: bitsToNibbles(keys[r]) });

        // undo AddConstants
        applyConstants(state, r - 1);               // XOR is its own inverse
        trace.push({ round: r, op: "AddConstants (Inv)", class: "op-AddConstants", nibbles: bitsToNibbles(state), keyNibbles: null });

        // undo PermBits
        state = applyPerm(state, PermInv);
        trace.push({ round: r, op: "PermBitsInv", class: "op-PermBitsInv", nibbles: bitsToNibbles(state), keyNibbles: null });

        // undo SubCells
        applySBox(state, SBoxInv);
        trace.push({ round: r, op: "SubCellsInv", class: "op-SubCellsInv", nibbles: bitsToNibbles(state), keyNibbles: null });
    }

    // undo whitening key
    for (let i = 0; i < 128; i++) state[i] ^= keys[0][i];
    trace.push({ round: 0, op: "Remove Whitening Key", class: "op-AddRoundKey", nibbles: bitsToNibbles(state), keyNibbles: bitsToNibbles(keys[0]) });

    trace.push({ round: 0, op: "Plaintext Recovered", class: "", nibbles: bitsToNibbles(state), keyNibbles: null });
    return trace;
}

let currentTrace = [];
let currentIndex = 0;
let playing = false;
let playInterval = null;
let currentMode = 'encrypt';

const valRound = document.getElementById("val-round");
const valStep = document.getElementById("val-step");
const valMode = document.getElementById("val-mode");
const flowchartContainer = document.getElementById("flowchart-container");

const btnEncrypt = document.getElementById("btn-encrypt");
const btnPrev = document.getElementById("btn-prev");
const btnPlay = document.getElementById("btn-play");
const btnNext = document.getElementById("btn-next");
const traceControls = document.getElementById("trace-controls");

const modeEncryptBtn = document.getElementById("mode-encrypt");
const modeDecryptBtn = document.getElementById("mode-decrypt");
const labelInput = document.getElementById("label-input");
const dataInput = document.getElementById("data-input");

function setMode(mode) {
    currentMode = mode;
    if (mode === 'encrypt') {
        modeEncryptBtn.classList.add('active');
        modeDecryptBtn.classList.remove('active');
        labelInput.textContent = "Plaintext (32 Hex Characters)";
        valMode.textContent = "ENCRYPT";
        valMode.classList.remove('decrypt-mode');
        btnEncrypt.textContent = "Initialize Trace";
    } else {
        modeDecryptBtn.classList.add('active');
        modeEncryptBtn.classList.remove('active');
        labelInput.textContent = "Ciphertext (32 Hex Characters)";
        valMode.textContent = "DECRYPT";
        valMode.classList.add('decrypt-mode');
        btnEncrypt.textContent = "Initialize Trace";
    }
    flowchartContainer.innerHTML = "";
    traceControls.style.display = "none";
    currentTrace = [];
    currentIndex = 0;
}

modeEncryptBtn.addEventListener("click", () => setMode('encrypt'));
modeDecryptBtn.addEventListener("click", () => setMode('decrypt'));

function createGridHTML(nibbles, extraClass) {
    let html = `<div class="state-grid ${extraClass}">`;
    for (let i = 0; i < 32; i++) {
        html += `<div class="nibble-box"><span class="index">${i}</span><span class="val">${nibbles[i]}</span></div>`;
    }
    html += `</div>`;
    return html;
}

function renderNextBlock() {
    if (currentIndex >= currentTrace.length) return;

    let step = currentTrace[currentIndex];

    let node = document.createElement("div");
    node.className = "flow-node";
    node.id = `node-${currentIndex}`;

    if (currentIndex > 0) {
        node.innerHTML += `<div class="flow-arrow">&#8595;</div>`;
    }

    let contentHtml = `<div class="flow-content">`;

    if (step.keyNibbles) {
        contentHtml += `
            <div class="flow-block op-KeySchedule">
                <h4>Round Key</h4>
                ${createGridHTML(step.keyNibbles, 'op-KeySchedule')}
            </div>
            <div class="flow-connector">&#10142;</div>
        `;
    }

    contentHtml += `
        <div class="flow-block ${step.class}">
            <h4>[Round ${step.round}] ${step.op}</h4>
            ${createGridHTML(step.nibbles, step.class)}
        </div>
    `;

    contentHtml += `</div>`;
    node.innerHTML += contentHtml;

    flowchartContainer.appendChild(node);
    flowchartContainer.scrollTo({ top: flowchartContainer.scrollHeight, behavior: 'smooth' });

    valRound.innerText = step.round;
    valStep.innerText = `${currentIndex} / ${currentTrace.length - 1}`;
}

function updateUI() {
    if (currentTrace.length === 0) return;

    if (currentIndex < flowchartContainer.children.length - 1) {
        while (flowchartContainer.children.length > currentIndex + 1) {
            flowchartContainer.removeChild(flowchartContainer.lastChild);
        }
        let step = currentTrace[currentIndex];
        valRound.innerText = step.round;
        valStep.innerText = `${currentIndex} / ${currentTrace.length - 1}`;
    } else if (currentIndex >= flowchartContainer.children.length) {
        renderNextBlock();
    }

    btnPrev.disabled = (currentIndex === 0);
    btnNext.disabled = (currentIndex === currentTrace.length - 1);

    if (currentIndex === currentTrace.length - 1 && playing) togglePlay();
}

function togglePlay() {
    playing = !playing;
    if (playing) {
        btnPlay.innerText = "Pause";
        if (currentIndex === currentTrace.length - 1) {
            currentIndex = 0;
            flowchartContainer.innerHTML = "";
            renderNextBlock();
        }
        playInterval = setInterval(() => {
            if (currentIndex < currentTrace.length - 1) {
                currentIndex++;
                updateUI();
            }
        }, 500);
    } else {
        btnPlay.innerText = "Play";
        clearInterval(playInterval);
    }
}

btnEncrypt.addEventListener("click", () => {
    let data = dataInput.value.padEnd(32, "0").substring(0, 32);
    let ky = document.getElementById("key").value.padEnd(32, "0").substring(0, 32);

    currentTrace = (currentMode === 'encrypt')
        ? generateEncryptTrace(data, ky)
        : generateDecryptTrace(data, ky);

    currentIndex = 0;
    flowchartContainer.innerHTML = "";
    traceControls.style.display = "block";

    updateUI();
});

btnPrev.addEventListener("click", () => {
    if (currentIndex > 0) { currentIndex--; updateUI(); }
});

btnNext.addEventListener("click", () => {
    if (currentIndex < currentTrace.length - 1) { currentIndex++; updateUI(); }
});

btnPlay.addEventListener("click", togglePlay);
