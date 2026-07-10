// =======================================================
// CodeGuard AI
// =======================================================

let currentVulnerabilities = [];
let acceptedIds = new Set();
let dismissedIds = new Set();

let currentFixedCode = "";
let originalCode = "";

// =======================================================
// API KEY
// =======================================================

function getApiKey() {
    return localStorage.getItem("gemini_api_key") || "";
}

function saveApiKey() {

    const key = document
        .getElementById("apiKeyInput")
        .value
        .trim();

    localStorage.setItem(
        "gemini_api_key",
        key
    );
}

document.addEventListener("DOMContentLoaded", () => {

    const saved = getApiKey();

    if (saved) {
        document.getElementById("apiKeyInput").value = saved;
    }

    updateLineNumbers();
});

// =======================================================
// CODE EDITOR
// =======================================================

const codeInput = document.getElementById("codeInput");
const lineNumbers = document.getElementById("lineNumbers");
const lineCount = document.getElementById("lineCount");

function updateLineNumbers() {

    const lines = codeInput.value.split("\n");

    lineNumbers.textContent = lines
        .map((_, i) => i + 1)
        .join("\n");

    lineCount.innerHTML =
        `<svg width="12" height="12" viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        stroke-width="2">

        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>

        <polyline points="14 2 14 8 20 8"/>

        </svg>

        ${lines.length} line${lines.length>1?"s":""}`;
}

codeInput.addEventListener(
    "input",
    updateLineNumbers
);

codeInput.addEventListener(
    "scroll",
    () => {

        lineNumbers.scrollTop =
            codeInput.scrollTop;

    }
);

function clearCode(){

    codeInput.value="";

    updateLineNumbers();

    resetResults();
}

// =======================================================
// ANALYZE
// =======================================================

async function analyzeCode(){

    const code = codeInput.value.trim();

    if(!code){

        alert("Please paste code.");

        return;
    }

    originalCode = code;

    const btn =
        document.getElementById("analyzeBtn");

    btn.disabled=true;

    btn.innerHTML="Scanning...";

    showLoading();

    try{

        const response =
            await fetch("/analyze",{

                method:"POST",

                headers:{

                    "Content-Type":"application/json",

                    "X-API-Key":getApiKey()

                },

                body:JSON.stringify({

                    code:code,

                    language:document.getElementById("languageSelect").value,

                    model:document.getElementById("modelSelect").value

                })

            });

        const data=await response.json();

        if(!response.ok){

            showError(data.error);

            return;
        }

        currentVulnerabilities =
            data.vulnerabilities || [];

        acceptedIds.clear();

        dismissedIds.clear();

        renderResults(data);

    }

    catch(err){

        console.error(err);

        showError(err.message);

    }

    finally{

        btn.disabled=false;

        btn.innerHTML="Scan for Vulnerabilities";

    }

}

// =======================================================
// RENDER RESULTS
// =======================================================

function renderResults(data){

    document
        .getElementById("loadingState")
        .classList.add("hidden");

    document
        .getElementById("emptyState")
        .classList.add("hidden");

    const badge =
        document.getElementById("overallRisk");

    badge.textContent =
        data.overall_risk || "UNKNOWN";

    badge.className =
        `risk-badge risk-${(data.overall_risk || "LOW").toLowerCase()}`;

    badge.classList.remove("hidden");

    document.getElementById("summaryText").textContent =
        data.summary || "";

    const list =
        document.getElementById("vulnList");

    list.innerHTML="";

    currentVulnerabilities.forEach(v=>{

        list.appendChild(
            createCard(v)
        );

    });

    document
        .getElementById("resultsArea")
        .classList.remove("hidden");

    updateApplySection();

}

// =======================================================
// CREATE CARD
// =======================================================

function createCard(v){

    const card=document.createElement("div");

    card.className="vuln-card";

    card.id=`card-${v.id}`;

    const sevIcon={

        CRITICAL:"🔴",

        HIGH:"🟠",

        MEDIUM:"🟡",

        LOW:"🟢"

    }[v.severity] || "⚪";

    card.innerHTML=`

<div class="vuln-card-header"
onclick="toggleCard(${v.id})">

<div class="vuln-num">

${v.id}

</div>

<div class="vuln-meta">

<div class="vuln-name">

${esc(v.title)}

</div>

<span class="sev-tag sev-${v.severity}">

${sevIcon}

${v.severity}

</span>

</div>

<svg
class="chevron"

width="16"

height="16"

viewBox="0 0 24 24"

fill="none"

stroke="currentColor"

stroke-width="2">

<polyline
points="6 9 12 15 18 9"/>

</svg>

</div>

<div
class="vuln-body"

id="body-${v.id}">

<p class="vuln-desc">

${esc(v.description)}

</p>

<div class="vuln-ref">

<b>Found:</b>

${esc(v.line_reference)}

</div>

<div class="vuln-ref">

<b>CWE:</b>

${esc(v.cwe || "N/A")}

</div>

<div class="vuln-ref">

<b>OWASP:</b>

${esc(v.owasp || "N/A")}

</div>

<div class="vuln-ref">

<b>Confidence:</b>

${esc(v.confidence || "N/A")}

</div>

<div class="suggestion-box">

<b>Impact</b>

<br>

${esc(v.impact || "")}

</div>

<div class="suggestion-box">

<b>Mitigation Methods</b>

<ul>

${(v.mitigations || [])

.map(x=>`<li>${esc(x)}</li>`)

.join("")}

</ul>

</div>

<div class="suggestion-box">

<b>Recommendation</b>

<br>

${esc(v.suggestion)}

</div>

<div class="vuln-actions">

<button

class="btn-accept"

id="ab-${v.id}"

onclick="toggleAccept(${v.id})">

✔ Accept Fix

</button>

<button

class="btn-dismiss"

onclick="dismissCard(${v.id})">

✖ Dismiss

</button>

</div>

</div>

`;

    return card;

}

// =======================================================
// CARD ACTIONS
// =======================================================

function toggleCard(id){

    const body=document.getElementById(`body-${id}`);

    const icon=document.querySelector(`#card-${id} .chevron`);

    if(body.classList.contains("open")){

        body.classList.remove("open");

        if(icon) icon.classList.remove("open");

    }else{

        body.classList.add("open");

        if(icon) icon.classList.add("open");

    }

}

// =======================================================
// ACCEPT FIX
// =======================================================

function toggleAccept(id){

    const card=document.getElementById(`card-${id}`);

    const btn=document.getElementById(`ab-${id}`);

    if(acceptedIds.has(id)){

        acceptedIds.delete(id);

        card.classList.remove("accepted");

        btn.innerHTML="✔ Accept Fix";

        btn.classList.remove("active");

    }

    else{

        acceptedIds.add(id);

        dismissedIds.delete(id);

        card.classList.add("accepted");

        card.classList.remove("dismissed");

        btn.innerHTML="✔ Accepted";

        btn.classList.add("active");

    }

    updateApplySection();

}

// =======================================================
// DISMISS
// =======================================================

function dismissCard(id){

    acceptedIds.delete(id);

    dismissedIds.add(id);

    const card=document.getElementById(`card-${id}`);

    card.classList.remove("accepted");

    card.classList.add("dismissed");

    const btn=document.getElementById(`ab-${id}`);

    btn.classList.remove("active");

    btn.innerHTML="✔ Accept Fix";

    updateApplySection();

}

// =======================================================
// APPLY SECTION
// =======================================================

function updateApplySection(){

    const sec=document.getElementById("applySection");

    const info=document.getElementById("acceptedInfo");

    if(acceptedIds.size===0){

        sec.classList.add("hidden");

        return;

    }

    sec.classList.remove("hidden");

    info.innerHTML=

        `${acceptedIds.size} fix accepted`;

}

// =======================================================
// APPLY ACCEPTED FIXES
// =======================================================

async function applyAllAccepted(){

    if(acceptedIds.size===0){

        alert("Please accept at least one fix.");

        return;

    }

    const btn=document.getElementById("applyAllBtn");

    btn.disabled=true;

    btn.innerHTML="Applying...";

    try{

        const selected=currentVulnerabilities.filter(v=>
            acceptedIds.has(v.id)
        );

        const response=await fetch("/apply-fix",{

            method:"POST",

            headers:{

                "Content-Type":"application/json",

                "X-API-Key":getApiKey()

            },

            body:JSON.stringify({

                original_code:originalCode,

                accepted_ids:Array.from(acceptedIds),

                all_fixes:selected,

                language:document.getElementById("languageSelect").value,

                model:document.getElementById("modelSelect").value

            })

        });

        const data=await response.json();

        if(!response.ok){

            throw new Error(data.error || "Failed to apply fixes");

        }

        currentFixedCode=data.fixed_code;

        showModal(currentFixedCode);

    }

    catch(err){

        console.error(err);

        showError(err.message);

    }

    finally{

        btn.disabled=false;

        btn.innerHTML="Apply Accepted Fixes";

    }

}

// =======================================================
// MODAL
// =======================================================

function showModal(code){

    document
        .getElementById("fixedCodeDisplay")
        .textContent=code;

    document
        .getElementById("modalOverlay")
        .classList.remove("hidden");

}

function closeModal(){

    document
        .getElementById("modalOverlay")
        .classList.add("hidden");

}

// =======================================================
// COPY
// =======================================================

async function copyFixed(){

    try{

        await navigator.clipboard.writeText(
            currentFixedCode
        );

        const btn=document.getElementById("copyBtn");

        btn.innerHTML="Copied ✓";

        setTimeout(()=>{

            btn.innerHTML="Copy Code";

        },1500);

    }

    catch{

        alert("Copy failed.");

    }

}

// =======================================================
// USE FIXED CODE
// =======================================================

function useFixedCode(){

    codeInput.value=currentFixedCode;

    updateLineNumbers();

    closeModal();

}

// =======================================================
// LOADING
// =======================================================

function showLoading(){

    document.getElementById("resultsArea").classList.add("hidden");
    document.getElementById("emptyState").classList.add("hidden");
    document.getElementById("loadingState").classList.remove("hidden");

}

// =======================================================
// ERROR
// =======================================================

function showError(message){

    document.getElementById("loadingState").classList.add("hidden");

    alert(message || "Unknown Error");

}

// =======================================================
// RESET
// =======================================================

function resetResults(){

    currentVulnerabilities=[];

    acceptedIds.clear();

    dismissedIds.clear();

    currentFixedCode="";

    document.getElementById("resultsArea").classList.add("hidden");

    document.getElementById("loadingState").classList.add("hidden");

    document.getElementById("overallRisk").classList.add("hidden");

    document.getElementById("emptyState").classList.remove("hidden");

}

// =======================================================
// HTML ESCAPE
// =======================================================

function esc(text){

    if(text===undefined || text===null)
        return "";

    return String(text)
        .replace(/&/g,"&amp;")
        .replace(/</g,"&lt;")
        .replace(/>/g,"&gt;")
        .replace(/"/g,"&quot;")
        .replace(/'/g,"&#039;");

}

// =======================================================
// SHORTCUT
// =======================================================

document.addEventListener("keydown",(e)=>{

    if(e.ctrlKey && e.key==="Enter"){

        e.preventDefault();

        analyzeCode();

    }

});

// =======================================================
// GLOBAL FUNCTIONS
// =======================================================

window.analyzeCode=analyzeCode;
window.clearCode=clearCode;
window.saveApiKey=saveApiKey;

window.toggleCard=toggleCard;
window.toggleAccept=toggleAccept;
window.dismissCard=dismissCard;

window.applyAllAccepted=applyAllAccepted;

window.closeModal=closeModal;
window.copyFixed=copyFixed;
window.useFixedCode=useFixedCode;

// =======================================================
// INIT
// =======================================================

updateLineNumbers();

console.log("✅ CodeGuard AI Loaded Successfully");