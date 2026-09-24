/**
 * AIShield - Frontend Client Logic (Modules 1, 2, & 3)
 */

document.addEventListener("DOMContentLoaded", () => {
    // Current completed analysis snapshot
    let currentAnalysisData = null;

    // DOM Elements - Input & Controls
    const inputText = document.getElementById("input-text");
    const charCount = document.getElementById("char-count");
    const wordCount = document.getElementById("word-count");
    const btnAnalyze = document.getElementById("btn-analyze");
    const btnSpinner = document.getElementById("btn-spinner");
    const btnTextLabel = document.getElementById("btn-text-label");
    const btnClear = document.getElementById("btn-clear");

    // Presets
    const btnSampleHuman = document.getElementById("btn-sample-human");
    const btnSampleAi = document.getElementById("btn-sample-ai");
    const btnSamplePhish = document.getElementById("btn-sample-phish");
    const btnSampleDisinfo = document.getElementById("btn-sample-disinfo");

    // Banners & Containers
    const errorBanner = document.getElementById("error-banner");
    const errorMessage = document.getElementById("error-message");
    const btnCloseError = document.getElementById("btn-close-error");
    const resultsSection = document.getElementById("results-section");

    // DOM Elements - MODULE 2: Threat Analysis & Risk Scoring
    const badgeCategory = document.getElementById("badge-category");
    const threatScoreVal = document.getElementById("threat-score-val");
    const riskLevelBadge = document.getElementById("risk-level-badge");
    const valThreatMeter = document.getElementById("val-threat-meter");
    const barThreatScore = document.getElementById("bar-threat-score");

    // Component score elements (all 7 score components)
    const compAi = document.getElementById("comp-ai");
    const barCompAi = document.getElementById("bar-comp-ai");
    const compUrgency = document.getElementById("comp-urgency");
    const barCompUrgency = document.getElementById("bar-comp-urgency");
    const compManipulation = document.getElementById("comp-manipulation");
    const barCompManipulation = document.getElementById("bar-comp-manipulation");
    const compCta = document.getElementById("comp-cta");
    const barCompCta = document.getElementById("bar-comp-cta");
    const compClaims = document.getElementById("comp-claims");
    const barCompClaims = document.getElementById("bar-comp-claims");
    const compAuthority = document.getElementById("comp-authority");
    const barCompAuthority = document.getElementById("bar-comp-authority");
    const compCatSeverity = document.getElementById("comp-cat-severity");
    const barCompCatSeverity = document.getElementById("bar-comp-cat-severity");

    // Indicators & Reasons lists
    const indicatorsList = document.getElementById("indicators-list");
    const reasonsList = document.getElementById("reasons-list");

    // DOM Elements - MODULE 1: AI Content Detection
    const predictionBadge = document.getElementById("prediction-badge");
    const predictionVerdict = document.getElementById("prediction-verdict");
    const confidenceMetric = document.getElementById("confidence-metric");
    const valAiProb = document.getElementById("val-ai-prob");
    const barAiProb = document.getElementById("bar-ai-prob");
    const valHumanProb = document.getElementById("val-human-prob");
    const barHumanProb = document.getElementById("bar-human-prob");

    // DOM Elements - MODULE 1: Text Statistics
    const metricChars = document.getElementById("metric-chars");
    const metricWords = document.getElementById("metric-words");
    const metricSentences = document.getElementById("metric-sentences");
    const metricAvgWordLen = document.getElementById("metric-avg-word-len");
    const metricAvgSentLen = document.getElementById("metric-avg-sent-len");
    const metricVocabRich = document.getElementById("metric-vocab-rich");
    const metricPunctCount = document.getElementById("metric-punct-count");
    const metricQuestionMarks = document.getElementById("metric-question-marks");
    const metricExclamationMarks = document.getElementById("metric-exclamation-marks");
    const metricRepeatedWords = document.getElementById("metric-repeated-words");

    // DOM Elements - MODULE 3: Digital Forensics & Save Incident
    const btnSaveIncident = document.getElementById("btn-save-incident");
    const btnSaveSpinner = document.getElementById("btn-save-spinner");
    const btnSaveLabel = document.getElementById("btn-save-label");
    const incidentSavedCard = document.getElementById("incident-saved-card");
    const savedIncidentId = document.getElementById("saved-incident-id");
    const savedIncidentTime = document.getElementById("saved-incident-time");
    const savedIncidentHash = document.getElementById("saved-incident-hash");
    const savedIncidentLink = document.getElementById("saved-incident-link");

    // Predefined samples for quick verification
    const SAMPLES = {
        human: "My grandmother used to make this incredible spicy tomato soup every autumn. She never wrote down any recipe, just tasted it with a wooden spoon and smiled.",
        ai: "In today's fast-paced digital era, artificial intelligence plays a crucial role in revolutionizing modern industries and optimizing operational workflows.",
        phishing: "Official Security Alert: Your account is suspended due to unauthorized login detected! Verify your account and confirm your password immediately by clicking the link within 24 hours.",
        disinformation: "Shocking truth: Leaked documents confirmed by insiders! They are hiding this secret information from the public. People need to know!"
    };

    // Readable names for indicator groups
    const INDICATOR_NAME_MAP = {
        urgency: "Urgency / Pressure",
        manipulation: "Manipulation",
        call_to_action: "Call to Action",
        unverified_claims: "Unverified Claims",
        authority_impersonation: "Authority Patterns",
        credential_phishing: "Credential Phishing"
    };

    /**
     * Update dynamic word and character counter
     */
    function updateCounters() {
        const text = inputText.value || "";
        charCount.textContent = text.length.toLocaleString();

        const words = text.trim().match(/\b\w+(?:'\w+)?\b/g);
        const count = words ? words.length : 0;
        wordCount.textContent = count.toLocaleString();
    }

    /**
     * Display error banner
     */
    function showError(message) {
        errorMessage.textContent = message;
        errorBanner.style.display = "flex";
    }

    /**
     * Hide error banner
     */
    function hideError() {
        errorBanner.style.display = "none";
        errorMessage.textContent = "";
    }

    /**
     * Set button loading state for analysis
     */
    function setLoading(isLoading) {
        if (isLoading) {
            btnAnalyze.disabled = true;
            btnAnalyze.classList.add("loading");
            btnTextLabel.textContent = "Analyzing...";
        } else {
            btnAnalyze.disabled = false;
            btnAnalyze.classList.remove("loading");
            btnTextLabel.textContent = "Analyze Content";
        }
    }

    /**
     * Render complete Modules 1 & 2 results safely to UI
     */
    function renderResults(data) {
        currentAnalysisData = data;
        const { prediction, text_analysis, threat_analysis } = data;

        // Reset Save Incident button state
        if (btnSaveIncident) {
            btnSaveIncident.disabled = false;
            if (btnSaveLabel) btnSaveLabel.textContent = "Save as Incident Record";
            if (btnSaveSpinner) btnSaveSpinner.style.display = "none";
        }
        if (incidentSavedCard) {
            incidentSavedCard.style.display = "none";
        }

        // ==========================================
        // MODULE 2: Threat Analysis & Risk Scoring
        // ==========================================
        if (threat_analysis) {
            const score = Number(threat_analysis.threat_score).toFixed(1);
            threatScoreVal.textContent = score;
            valThreatMeter.textContent = `${score}%`;
            barThreatScore.style.width = `${Math.min(100, Math.max(0, threat_analysis.threat_score))}%`;

            const level = (threat_analysis.risk_level || "LOW").toUpperCase();
            riskLevelBadge.textContent = level;
            riskLevelBadge.className = `risk-badge risk-${level.toLowerCase()}`;
            riskLevelBadge.setAttribute("aria-label", `Risk Level: ${level}`);

            badgeCategory.textContent = threat_analysis.category || "Normal";

            // Component Signals (7 distinct components)
            const comps = threat_analysis.component_scores || {};
            const setComp = (elText, elBar, val) => {
                if (elText && elBar) {
                    const num = Number(val || 0);
                    elText.textContent = num.toFixed(1);
                    elBar.style.width = `${Math.min(100, Math.max(0, num))}%`;
                }
            };

            setComp(compAi, barCompAi, comps.ai_likelihood);
            setComp(compUrgency, barCompUrgency, comps.urgency);
            setComp(compManipulation, barCompManipulation, comps.manipulation);
            setComp(compCta, barCompCta, comps.call_to_action);
            setComp(compClaims, barCompClaims, comps.unverified_claims);
            setComp(compAuthority, barCompAuthority, comps.authority_patterns);
            setComp(compCatSeverity, barCompCatSeverity, comps.category_severity);

            // Detected Indicators List (Safe DOM creation)
            while (indicatorsList.firstChild) {
                indicatorsList.removeChild(indicatorsList.firstChild);
            }

            const indicators = threat_analysis.indicators || [];
            if (indicators.length === 0) {
                const emptyNote = document.createElement("p");
                emptyNote.className = "no-indicators-note";
                emptyNote.textContent = "No significant manipulation or deceptive threat indicators detected.";
                indicatorsList.appendChild(emptyNote);
            } else {
                indicators.forEach((ind) => {
                    const row = document.createElement("div");
                    row.className = "indicator-row";

                    const left = document.createElement("div");
                    left.className = "indicator-left";

                    const nameTag = document.createElement("span");
                    nameTag.className = "indicator-type-tag";
                    nameTag.textContent = INDICATOR_NAME_MAP[ind.type] || ind.type.replace(/_/g, " ");

                    const desc = document.createElement("span");
                    desc.className = "indicator-desc";
                    desc.textContent = ind.description;

                    left.appendChild(nameTag);
                    left.appendChild(desc);

                    const sevBadge = document.createElement("span");
                    const sevUpper = (ind.severity || "low").toUpperCase();
                    sevBadge.className = `indicator-severity-badge sev-${ind.severity}`;
                    sevBadge.textContent = `${sevUpper} (${ind.count})`;
                    sevBadge.setAttribute("aria-label", `Severity: ${sevUpper}, Count: ${ind.count}`);

                    row.appendChild(left);
                    row.appendChild(sevBadge);
                    indicatorsList.appendChild(row);
                });
            }

            // Why this score? (Reasons List - Safe DOM creation)
            while (reasonsList.firstChild) {
                reasonsList.removeChild(reasonsList.firstChild);
            }

            const reasons = threat_analysis.reasons || [];
            reasons.forEach((reasonText) => {
                const li = document.createElement("li");
                li.textContent = reasonText;
                reasonsList.appendChild(li);
            });
        }

        // ==========================================
        // MODULE 1: AI Content Detection
        // ==========================================
        if (prediction) {
            const isAi = prediction.label.toLowerCase().includes("ai");
            predictionVerdict.textContent = prediction.label;
            predictionVerdict.className = `prediction-value ${isAi ? "ai-text" : "human-text"}`;

            predictionBadge.textContent = isAi ? "AI-Generated" : "Human";
            predictionBadge.className = `badge ${isAi ? "badge-ai" : "badge-human"}`;

            const confPct = (prediction.confidence * 100).toFixed(1);
            confidenceMetric.textContent = `${confPct}%`;

            const aiPct = (prediction.ai_probability * 100).toFixed(1);
            valAiProb.textContent = `${aiPct}%`;
            barAiProb.style.width = `${Math.min(100, Math.max(0, prediction.ai_probability * 100))}%`;

            const humanPct = (prediction.human_probability * 100).toFixed(1);
            valHumanProb.textContent = `${humanPct}%`;
            barHumanProb.style.width = `${Math.min(100, Math.max(0, prediction.human_probability * 100))}%`;
        }

        // ==========================================
        // MODULE 1: Structural Text Analysis
        // ==========================================
        if (text_analysis) {
            metricChars.textContent = text_analysis.character_count.toLocaleString();
            metricWords.textContent = text_analysis.word_count.toLocaleString();
            metricSentences.textContent = text_analysis.sentence_count.toLocaleString();
            metricAvgWordLen.textContent = Number(text_analysis.average_word_length).toFixed(2);
            metricAvgSentLen.textContent = Number(text_analysis.average_sentence_length).toFixed(1);
            metricVocabRich.textContent = `${(Number(text_analysis.vocabulary_richness) * 100).toFixed(1)}%`;
            metricPunctCount.textContent = text_analysis.punctuation_count.toLocaleString();
            metricQuestionMarks.textContent = text_analysis.question_mark_count.toLocaleString();
            metricExclamationMarks.textContent = text_analysis.exclamation_mark_count.toLocaleString();
            metricRepeatedWords.textContent = text_analysis.repeated_word_count.toLocaleString();
        }

        resultsSection.style.display = "flex";
        if (window.AIShieldAnimate) {
            window.AIShieldAnimate.revealElement(resultsSection);
        }
        resultsSection.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }

    /**
     * Submit text for analysis
     */
    async function handleAnalyze() {
        hideError();
        const text = inputText.value.trim();

        if (!text) {
            resultsSection.style.display = "none";
            showError("Please enter or paste some text before clicking analyze.");
            inputText.focus();
            return;
        }

        setLoading(true);

        try {
            const response = await fetch("/api/analyze", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({ text: text }),
            });

            const result = await response.json();

            if (!response.ok || !result.success) {
                // Prevent showing stale results on error
                resultsSection.style.display = "none";
                const errMsg = result.error || `Server returned error (${response.status})`;
                showError(errMsg);
            } else {
                renderResults(result);
            }
        } catch (err) {
            // Prevent showing stale results on network failure
            resultsSection.style.display = "none";
            showError("Network error: Unable to connect to the analysis service. Please ensure the server is running.");
        } finally {
            setLoading(false);
        }
    }

    /**
     * Save Current Analysis as a Forensic Incident Record (Module 3)
     */
    async function handleSaveIncident() {
        if (!currentAnalysisData) {
            showError("No analysis data available to save. Please run analysis first.");
            return;
        }

        const rawText = inputText.value;
        if (!rawText || !rawText.trim()) {
            showError("Cannot save empty text as an incident.");
            return;
        }

        btnSaveIncident.disabled = true;
        if (btnSaveSpinner) btnSaveSpinner.style.display = "inline-block";
        if (btnSaveLabel) btnSaveLabel.textContent = "Saving...";

        try {
            const response = await fetch("/api/incidents", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    text: rawText,
                    prediction: currentAnalysisData.prediction,
                    text_analysis: currentAnalysisData.text_analysis,
                    threat_analysis: currentAnalysisData.threat_analysis,
                }),
            });

            const result = await response.json();

            if (response.ok && result.success && result.incident) {
                const inc = result.incident;
                savedIncidentId.textContent = inc.incident_id;
                savedIncidentTime.textContent = inc.created_at;
                savedIncidentHash.textContent = inc.content_hash;
                savedIncidentLink.href = `/incidents/${encodeURIComponent(inc.incident_id)}`;

                incidentSavedCard.style.display = "flex";
                if (btnSaveLabel) btnSaveLabel.textContent = "Saved to Database ✓";
                incidentSavedCard.scrollIntoView({ behavior: "smooth", block: "nearest" });
            } else {
                showError(result.error || "Failed to save forensic incident record.");
                btnSaveIncident.disabled = false;
                if (btnSaveLabel) btnSaveLabel.textContent = "Save as Incident Record";
            }
        } catch (err) {
            showError("Network error: Unable to save incident record to server.");
            btnSaveIncident.disabled = false;
            if (btnSaveLabel) btnSaveLabel.textContent = "Save as Incident Record";
        } finally {
            if (btnSaveSpinner) btnSaveSpinner.style.display = "none";
        }
    }

    /**
     * Clear inputs and results
     */
    function handleClear() {
        inputText.value = "";
        currentAnalysisData = null;
        updateCounters();
        hideError();
        resultsSection.style.display = "none";
        inputText.focus();
    }

    /**
     * Event Listeners
     */
    inputText.addEventListener("input", updateCounters);
    btnAnalyze.addEventListener("click", handleAnalyze);
    btnClear.addEventListener("click", handleClear);
    btnCloseError.addEventListener("click", hideError);

    if (btnSaveIncident) {
        btnSaveIncident.addEventListener("click", handleSaveIncident);
    }

    btnSampleHuman.addEventListener("click", () => {
        inputText.value = SAMPLES.human;
        updateCounters();
        hideError();
    });

    btnSampleAi.addEventListener("click", () => {
        inputText.value = SAMPLES.ai;
        updateCounters();
        hideError();
    });

    btnSamplePhish.addEventListener("click", () => {
        inputText.value = SAMPLES.phishing;
        updateCounters();
        hideError();
    });

    btnSampleDisinfo.addEventListener("click", () => {
        inputText.value = SAMPLES.disinformation;
        updateCounters();
        hideError();
    });

    // Keyboard shortcut (Ctrl+Enter / Cmd+Enter to analyze)
    inputText.addEventListener("keydown", (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
            e.preventDefault();
            handleAnalyze();
        }
    });

    // Initial counter update
    updateCounters();
});
