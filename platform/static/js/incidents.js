/**
 * AIShield - Digital Forensics & Incident History Client Logic (Module 3)
 */

document.addEventListener("DOMContentLoaded", () => {
    // =========================================================================
    // 1. Incident History Table Controller (for incidents.html)
    // =========================================================================
    const incidentsTable = document.getElementById("incidents-table");
    const incidentsTbody = document.getElementById("incidents-tbody");
    const btnRefreshHistory = document.getElementById("btn-refresh-history");
    const historySpinner = document.getElementById("history-spinner");

    if (incidentsTbody) {
        async function loadIncidentHistory() {
            if (historySpinner) historySpinner.style.display = "inline-block";

            while (incidentsTbody.firstChild) {
                incidentsTbody.removeChild(incidentsTbody.firstChild);
            }

            const loadingRow = document.createElement("tr");
            const loadingCell = document.createElement("td");
            loadingCell.colSpan = 8;
            loadingCell.className = "table-empty-message";
            loadingCell.textContent = "Loading stored incident records from database...";
            loadingRow.appendChild(loadingCell);
            incidentsTbody.appendChild(loadingRow);

            try {
                const response = await fetch("/api/incidents?limit=100");
                const data = await response.json();

                while (incidentsTbody.firstChild) {
                    incidentsTbody.removeChild(incidentsTbody.firstChild);
                }

                if (!response.ok || !data.success || !data.incidents || data.incidents.length === 0) {
                    const emptyRow = document.createElement("tr");
                    const emptyCell = document.createElement("td");
                    emptyCell.colSpan = 8;
                    emptyCell.className = "table-empty-message";

                    const emptyBox = document.createElement("div");
                    emptyBox.className = "empty-state-box";

                    const emptyIcon = document.createElement("div");
                    emptyIcon.className = "empty-state-icon";
                    emptyIcon.textContent = "📁";

                    const emptyText = document.createElement("p");
                    emptyText.className = "empty-state-text";
                    emptyText.textContent = "No incidents have been saved yet.";

                    const emptyLink = document.createElement("a");
                    emptyLink.className = "btn btn-primary btn-sm";
                    emptyLink.href = "/";
                    emptyLink.textContent = "Open Analyzer to Evaluate & Save Text";

                    emptyBox.appendChild(emptyIcon);
                    emptyBox.appendChild(emptyText);
                    emptyBox.appendChild(emptyLink);
                    emptyCell.appendChild(emptyBox);
                    emptyRow.appendChild(emptyCell);
                    incidentsTbody.appendChild(emptyRow);
                    return;
                }

                data.incidents.forEach((inc) => {
                    const tr = document.createElement("tr");

                    // Incident ID
                    const tdId = document.createElement("td");
                    const idSpan = document.createElement("span");
                    idSpan.className = "id-tag";
                    idSpan.textContent = inc.incident_id;
                    tdId.appendChild(idSpan);

                    // Timestamp
                    const tdTime = document.createElement("td");
                    tdTime.className = "font-mono";
                    const dt = new Date(inc.created_at);
                    tdTime.textContent = isNaN(dt.getTime()) ? inc.created_at : dt.toISOString().replace("T", " ").substring(0, 19) + " UTC";

                    // Category
                    const tdCat = document.createElement("td");
                    const catBadge = document.createElement("span");
                    catBadge.className = "badge badge-category";
                    catBadge.textContent = inc.category;
                    tdCat.appendChild(catBadge);

                    // Risk Level (Accessible text label)
                    const tdRisk = document.createElement("td");
                    const riskBadge = document.createElement("span");
                    const rLevel = (inc.risk_level || "LOW").toUpperCase();
                    riskBadge.className = `risk-badge risk-${rLevel.toLowerCase()}`;
                    riskBadge.style.fontSize = "0.75rem";
                    riskBadge.style.padding = "0.2rem 0.55rem";
                    riskBadge.textContent = rLevel;
                    riskBadge.setAttribute("aria-label", `Risk level: ${rLevel}`);
                    tdRisk.appendChild(riskBadge);

                    // Threat Score
                    const tdScore = document.createElement("td");
                    tdScore.className = "font-mono";
                    tdScore.textContent = `${Number(inc.threat_score).toFixed(1)}`;

                    // AI Prob
                    const tdAi = document.createElement("td");
                    tdAi.className = "font-mono";
                    tdAi.textContent = `${(Number(inc.ai_probability) * 100).toFixed(1)}%`;

                    // Hash preview
                    const tdHash = document.createElement("td");
                    const hashSpan = document.createElement("span");
                    hashSpan.className = "hash-preview";
                    const h = inc.content_hash || "";
                    hashSpan.textContent = h.length > 12 ? `${h.substring(0, 6)}...${h.substring(h.length - 6)}` : h;
                    hashSpan.title = h;
                    tdHash.appendChild(hashSpan);

                    // Action (View Detail)
                    const tdAction = document.createElement("td");
                    const viewLink = document.createElement("a");
                    viewLink.className = "btn btn-secondary btn-sm";
                    viewLink.href = `/incidents/${encodeURIComponent(inc.incident_id)}`;
                    viewLink.textContent = "View";
                    tdAction.appendChild(viewLink);

                    tr.appendChild(tdId);
                    tr.appendChild(tdTime);
                    tr.appendChild(tdCat);
                    tr.appendChild(tdRisk);
                    tr.appendChild(tdScore);
                    tr.appendChild(tdAi);
                    tr.appendChild(tdHash);
                    tr.appendChild(tdAction);

                    incidentsTbody.appendChild(tr);
                });
            } catch (err) {
                while (incidentsTbody.firstChild) {
                    incidentsTbody.removeChild(incidentsTbody.firstChild);
                }
                const errRow = document.createElement("tr");
                const errCell = document.createElement("td");
                errCell.colSpan = 8;
                errCell.className = "table-empty-message";
                errCell.textContent = "Failed to load incident history. Please ensure the server is running.";
                errRow.appendChild(errCell);
                incidentsTbody.appendChild(errRow);
            } finally {
                if (historySpinner) historySpinner.style.display = "none";
            }
        }

        loadIncidentHistory();

        if (btnRefreshHistory) {
            btnRefreshHistory.addEventListener("click", loadIncidentHistory);
        }
    }

    // =========================================================================
    // 2. Incident Detail Verification Controller (for incident_detail.html)
    // =========================================================================
    const btnVerifyIntegrity = document.getElementById("btn-verify-integrity");
    const verifySpinner = document.getElementById("verify-spinner");
    const verifyBtnLabel = document.getElementById("verify-btn-label");
    const verificationBanner = document.getElementById("verification-banner");
    const verifIcon = document.getElementById("verif-icon");
    const verifTitle = document.getElementById("verif-title");
    const verifDesc = document.getElementById("verif-desc");
    const verifStoredHash = document.getElementById("verif-stored-hash");
    const verifCalcHash = document.getElementById("verif-calc-hash");

    if (btnVerifyIntegrity) {
        btnVerifyIntegrity.addEventListener("click", async () => {
            const incidentId = btnVerifyIntegrity.getAttribute("data-incident-id");
            if (!incidentId) return;

            btnVerifyIntegrity.disabled = true;
            if (verifySpinner) verifySpinner.style.display = "inline-block";
            if (verifyBtnLabel) verifyBtnLabel.textContent = "Verifying...";

            try {
                const response = await fetch(`/api/incidents/${encodeURIComponent(incidentId)}/verify`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                });
                const result = await response.json();

                verificationBanner.style.display = "flex";

                if (verifStoredHash) verifStoredHash.textContent = result.stored_hash || "--";
                if (verifCalcHash) verifCalcHash.textContent = result.calculated_hash || "--";

                if (response.ok && result.success && result.verified) {
                    verificationBanner.className = "verification-banner verif-verified";
                    verifIcon.textContent = "✅";
                    verifTitle.textContent = "Integrity Verified";
                    verifDesc.textContent = "Calculated SHA-256 hash matches the recorded fingerprint. Stored bytes have not been altered.";
                } else {
                    verificationBanner.className = "verification-banner verif-failed";
                    verifIcon.textContent = "❌";
                    verifTitle.textContent = "Integrity Check Failed";
                    verifDesc.textContent = "Calculated hash does NOT match the stored fingerprint. Database record content has been altered out-of-band.";
                }
            } catch (err) {
                verificationBanner.style.display = "flex";
                verificationBanner.className = "verification-banner verif-failed";
                verifIcon.textContent = "⚠️";
                verifTitle.textContent = "Verification Request Error";
                verifDesc.textContent = "Unable to connect to verification endpoint. Please ensure the server is running.";
            } finally {
                btnVerifyIntegrity.disabled = false;
                if (verifySpinner) verifySpinner.style.display = "none";
                if (verifyBtnLabel) verifyBtnLabel.textContent = "🔍 Re-Verify Integrity";
            }
        });
    }

    // =========================================================================
    // 3. Safe Copy-to-Clipboard Controller
    // =========================================================================
    document.querySelectorAll(".btn-copy").forEach((btn) => {
        btn.addEventListener("click", async () => {
            const targetId = btn.getAttribute("data-copy-target");
            const targetEl = document.getElementById(targetId);
            if (!targetEl) return;

            const textToCopy = targetEl.textContent || targetEl.innerText || "";
            try {
                await navigator.clipboard.writeText(textToCopy);
                const origText = btn.textContent;
                btn.textContent = "Copied!";
                btn.classList.add("btn-primary");
                btn.classList.remove("btn-secondary");
                setTimeout(() => {
                    btn.textContent = origText;
                    btn.classList.remove("btn-primary");
                    btn.classList.add("btn-secondary");
                }, 2000);
            } catch (err) {
                btn.textContent = "Error";
                setTimeout(() => { btn.textContent = "Copy"; }, 2000);
            }
        });
    });
});
