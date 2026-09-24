/**
 * AIShield - Stage 6G Live Monitoring Dashboard Controller.
 *
 * Implements real-time Server-Sent Events (SSE) streaming with graceful
 * polling fallback, strict DOM safety (no innerHTML for untrusted content),
 * live metric counters, connector status cards, and high-risk incident alerts.
 */

document.addEventListener("DOMContentLoaded", () => {
    // --- State & DOM References ---
    let eventSource = null;
    let isPollingFallback = false;
    let pollIntervalId = null;
    let currentSourceFilter = "all";
    const MAX_FEED_ROWS = 50;
    const feedEvents = [];

    // Header & Status elements
    const streamPulse = document.getElementById("stream-pulse");
    const streamStatusText = document.getElementById("stream-status-text");
    const subscribersCountBadge = document.getElementById("subscribers-count-badge");

    // Incident Alert elements
    const liveAlertContainer = document.getElementById("live-alert-container");
    const alertTimestamp = document.getElementById("alert-timestamp");
    const alertSource = document.getElementById("alert-source");
    const alertAuthor = document.getElementById("alert-author");
    const alertRisk = document.getElementById("alert-risk");
    const alertThreatScore = document.getElementById("alert-threat-score");
    const alertAiProb = document.getElementById("alert-ai-prob");
    const alertCategory = document.getElementById("alert-category");
    const alertIncidentId = document.getElementById("alert-incident-id");
    const btnViewAlertIncident = document.getElementById("btn-view-alert-incident");
    const btnDismissAlert = document.getElementById("btn-dismiss-alert");

    // Connector Status elements
    const statusBluesky = document.getElementById("status-bluesky");
    const metaBlueskyEvents = document.getElementById("meta-bluesky-events");
    const metaBlueskyAccepted = document.getElementById("meta-bluesky-accepted");
    const metaBlueskyFiltered = document.getElementById("meta-bluesky-filtered");
    const metaBlueskyErrors = document.getElementById("meta-bluesky-errors");
    const statusMastodon = document.getElementById("status-mastodon");
    const metaMastodonEvents = document.getElementById("meta-mastodon-events");
    const metaMastodonAccepted = document.getElementById("meta-mastodon-accepted");
    const metaMastodonDedup = document.getElementById("meta-mastodon-dedup");
    const metaMastodonErrors = document.getElementById("meta-mastodon-errors");
    const metaMastodonStreams = document.getElementById("meta-mastodon-streams");
    const metaMastodonTagCount = document.getElementById("meta-mastodon-tag-count");
    const metaMastodonHashtags = document.getElementById("meta-mastodon-hashtags");
    const statusYoutube = document.getElementById("status-youtube");
    const metaYoutubeEvents = document.getElementById("meta-youtube-events");
    const metaYoutubeAccepted = document.getElementById("meta-youtube-accepted");
    const metaYoutubeDedup = document.getElementById("meta-youtube-dedup");
    const metaYoutubeRequests = document.getElementById("meta-youtube-requests");
    const metaYoutubeErrors = document.getElementById("meta-youtube-errors");
    const statusWorker = document.getElementById("status-worker");
    const metaWorkerThreads = document.getElementById("meta-worker-threads");
    const metaWorkerQueue = document.getElementById("meta-worker-queue");

    // Metrics elements
    const metricReceived = document.getElementById("metric-received");
    const metricAccepted = document.getElementById("metric-accepted");
    const metricDeduplicated = document.getElementById("metric-deduplicated");
    const metricDropped = document.getElementById("metric-dropped");
    const metricQueued = document.getElementById("metric-queued");
    const metricProcessing = document.getElementById("metric-processing");
    const metricAnalyzed = document.getElementById("metric-analyzed");
    const metricSkipped = document.getElementById("metric-skipped");
    const metricFailed = document.getElementById("metric-failed");
    const metricIncidents = document.getElementById("metric-incidents");

    // Feed table elements
    const liveFeedBody = document.getElementById("live-feed-body");
    const filterButtons = document.querySelectorAll(".btn-filter");

    // Dismiss Alert Event Listener
    if (btnDismissAlert) {
        btnDismissAlert.addEventListener("click", () => {
            liveAlertContainer.style.display = "none";
        });
    }

    // Source Filter Event Listeners
    filterButtons.forEach((btn) => {
        btn.addEventListener("click", () => {
            filterButtons.forEach((b) => b.classList.remove("active"));
            btn.classList.add("active");
            currentSourceFilter = btn.getAttribute("data-source") || "all";
            renderFeedRows();
        });
    });

    // --- Helper Functions ---

    function formatTime(isoStr) {
        if (!isoStr) return "-";
        try {
            const d = new Date(isoStr);
            return d.toTimeString().split(" ")[0];
        } catch {
            return String(isoStr).substring(11, 19);
        }
    }

    function setBadgeClass(elem, statusStr) {
        if (!elem) return;
        const s = (statusStr || "DISABLED").toUpperCase();
        elem.textContent = s;
        elem.className = "connector-badge";

        if (s === "CONNECTED" || s === "PROCESSING") {
            elem.classList.add("badge-connected");
        } else if (s === "POLLING") {
            elem.classList.add("badge-polling");
        } else if (s === "IDLE") {
            elem.classList.add("badge-idle");
        } else if (s === "CONNECTING") {
            elem.classList.add("badge-connecting");
        } else if (s === "ERROR") {
            elem.classList.add("badge-error");
        } else if (s === "DISCONNECTED") {
            elem.classList.add("badge-disconnected");
        } else {
            elem.classList.add("badge-disabled");
        }
    }

    function updateConnectorCards(states, metrics) {
        if (!states) return;

        // Bluesky
        if (states.bluesky) {
            setBadgeClass(statusBluesky, states.bluesky.state || states.bluesky.status);
            if (metaBlueskyEvents) metaBlueskyEvents.textContent = String(states.bluesky.events_received || 0);
            if (metaBlueskyAccepted) metaBlueskyAccepted.textContent = String(states.bluesky.events_accepted || 0);
            if (metaBlueskyFiltered) metaBlueskyFiltered.textContent = String(states.bluesky.events_filtered || 0);
            if (metaBlueskyErrors) metaBlueskyErrors.textContent = String(states.bluesky.connection_errors || 0);
        }

        // Mastodon
        if (states.mastodon) {
            setBadgeClass(statusMastodon, states.mastodon.state || states.mastodon.status);
            if (metaMastodonEvents) metaMastodonEvents.textContent = String(states.mastodon.events_received || 0);
            if (metaMastodonAccepted) metaMastodonAccepted.textContent = String(states.mastodon.events_accepted || 0);
            if (metaMastodonDedup) metaMastodonDedup.textContent = String(states.mastodon.events_deduplicated || 0);
            if (metaMastodonErrors) metaMastodonErrors.textContent = String(states.mastodon.connection_errors || 0);
            if (metaMastodonStreams) metaMastodonStreams.textContent = String(states.mastodon.active_streams ?? (states.mastodon.running ? (states.mastodon.hashtags_count || 1) : 0));
            if (metaMastodonTagCount) metaMastodonTagCount.textContent = String(states.mastodon.hashtags_count ?? (states.mastodon.hashtags ? states.mastodon.hashtags.length : 0));
            if (metaMastodonHashtags) {
                const tagList = states.mastodon.monitoring_hashtags || (states.mastodon.hashtags ? states.mastodon.hashtags.join(", ") : "-");
                metaMastodonHashtags.textContent = tagList;
                metaMastodonHashtags.title = tagList;
            }
        }

        // YouTube
        if (states.youtube) {
            setBadgeClass(statusYoutube, states.youtube.state || states.youtube.status);
            if (metaYoutubeEvents) metaYoutubeEvents.textContent = String(states.youtube.events_received ?? states.youtube.items_received ?? 0);
            if (metaYoutubeAccepted) metaYoutubeAccepted.textContent = String(states.youtube.events_accepted ?? states.youtube.items_accepted ?? 0);
            if (metaYoutubeDedup) metaYoutubeDedup.textContent = String(states.youtube.events_deduplicated ?? states.youtube.items_deduplicated ?? 0);
            if (metaYoutubeRequests) metaYoutubeRequests.textContent = `${states.youtube.requests_today || 0}/${states.youtube.max_requests_per_day || 100}`;
            if (metaYoutubeErrors) metaYoutubeErrors.textContent = String((states.youtube.connection_errors || 0) + (states.youtube.quota_errors || 0));
        }

        // Worker
        if (states.worker) {
            setBadgeClass(statusWorker, states.worker.state || states.worker.status);
        }
        if (metaWorkerThreads) {
            const active = states.worker ? (states.worker.active_workers ?? 1) : 1;
            metaWorkerThreads.textContent = String(active);
        }
        if (metaWorkerQueue) {
            const qSize = metrics && metrics.queue_size !== undefined ? metrics.queue_size : 0;
            metaWorkerQueue.textContent = `${qSize} items`;
        }
    }

    function updateMetrics(data) {
        if (!data) return;

        if (metricReceived) metricReceived.textContent = String(data.source_posts_received ?? 0);
        if (metricAccepted) metricAccepted.textContent = String(data.source_posts_received ?? 0);
        if (metricDeduplicated) metricDeduplicated.textContent = String(data.pipeline_metrics?.duplicate_posts ?? 0);
        if (metricDropped) metricDropped.textContent = String(data.pipeline_metrics?.dropped_posts ?? 0);
        if (metricQueued) metricQueued.textContent = String(data.queue_size ?? 0);
        if (metricProcessing) metricProcessing.textContent = String(data.active_workers ?? 0);
        if (metricAnalyzed) metricAnalyzed.textContent = String(data.source_posts_analyzed ?? 0);
        if (metricSkipped) metricSkipped.textContent = String(data.source_posts_skipped ?? 0);
        if (metricFailed) metricFailed.textContent = String(data.source_posts_failed ?? 0);
        if (metricIncidents) metricIncidents.textContent = String(data.incidents_generated ?? 0);
    }

    function showAlert(alertData) {
        if (!alertData || !liveAlertContainer) return;

        alertTimestamp.textContent = formatTime(alertData.created_at || new Date().toISOString());
        alertSource.textContent = String(alertData.source || "Unknown").toUpperCase();
        if (alertAuthor) {
            alertAuthor.textContent = String(alertData.author_name || alertData.author_id || "Anonymous");
        }

        const risk = String(alertData.risk_level || "HIGH").toUpperCase();
        alertRisk.textContent = risk;
        alertRisk.className = `alert-item-val risk-pill risk-${risk.toLowerCase()}`;

        alertThreatScore.textContent = `${Number(alertData.threat_score || 0).toFixed(1)} / 100`;
        alertAiProb.textContent = `${(Number(alertData.ai_probability || 0) * 100).toFixed(1)}%`;
        alertCategory.textContent = String(alertData.category || "Threat");
        alertIncidentId.textContent = String(alertData.incident_id || "-");

        if (alertData.incident_id && btnViewAlertIncident) {
            btnViewAlertIncident.href = `/incidents/${encodeURIComponent(alertData.incident_id)}`;
            btnViewAlertIncident.style.display = "inline-flex";
        } else if (btnViewAlertIncident) {
            btnViewAlertIncident.style.display = "none";
        }

        liveAlertContainer.style.display = "block";
    }

    // --- Strict Safe DOM Construction for Feed Table ---

    function createFeedRow(post, isNew = false) {
        const tr = document.createElement("tr");
        if (isNew) tr.classList.add("row-new");

        // 1. Time Cell
        const tdTime = document.createElement("td");
        tdTime.className = "time-cell";
        const timeVal = post.processed_at || post.ingested_at || post.created_at || post.timestamp || post.published_at;
        tdTime.textContent = formatTime(timeVal);
        tr.appendChild(tdTime);

        // 2. Source Cell
        const tdSource = document.createElement("td");
        const sourceBadge = document.createElement("span");
        const srcName = String(post.source || "manual").toLowerCase();
        sourceBadge.className = `source-badge source-${srcName}`;
        sourceBadge.textContent = srcName;
        tdSource.appendChild(sourceBadge);
        tr.appendChild(tdSource);

        // 3. Author Cell
        const tdAuthor = document.createElement("td");
        const authorText = String(post.author_name || post.author_id || "Anonymous");
        const srcLower = String(post.source || "").toLowerCase();

        if (srcLower === "bluesky") {
            const link = document.createElement("a");
            const targetHandle = (post.author_id || authorText).replace(/^@/, "");
            link.href = `https://bsky.app/profile/${encodeURIComponent(targetHandle)}`;
            link.target = "_blank";
            link.rel = "noopener noreferrer";
            link.className = "author-profile-link";
            link.textContent = authorText;
            link.title = `Open Bluesky profile for ${authorText}`;
            tdAuthor.appendChild(link);
        } else {
            tdAuthor.textContent = authorText;
        }
        tr.appendChild(tdAuthor);

        // 4. Status Cell
        const tdStatus = document.createElement("td");
        const statusBadge = document.createElement("span");
        const stName = String(post.status || "ANALYZED").toLowerCase();
        statusBadge.className = `status-badge status-${stName}`;
        statusBadge.textContent = String(post.status || "ANALYZED").toUpperCase();
        tdStatus.appendChild(statusBadge);
        tr.appendChild(tdStatus);

        // 5. AI Probability Cell
        const tdAi = document.createElement("td");
        if (post.ai_probability !== undefined && post.ai_probability !== null) {
            tdAi.textContent = `${(Number(post.ai_probability) * 100).toFixed(1)}%`;
        } else {
            tdAi.textContent = "-";
        }
        tr.appendChild(tdAi);

        // 6. Threat Score Cell
        const tdThreat = document.createElement("td");
        tdThreat.className = "threat-score-cell";
        if (post.threat_score !== undefined && post.threat_score !== null) {
            tdThreat.textContent = Number(post.threat_score).toFixed(1);
        } else {
            tdThreat.textContent = "-";
        }
        tr.appendChild(tdThreat);

        // 7. Risk Level Cell
        const tdRisk = document.createElement("td");
        if (post.risk_level) {
            const riskPill = document.createElement("span");
            const rk = String(post.risk_level).toLowerCase();
            riskPill.className = `risk-pill risk-${rk}`;
            riskPill.textContent = String(post.risk_level).toUpperCase();
            tdRisk.appendChild(riskPill);
        } else {
            tdRisk.textContent = "-";
        }
        tr.appendChild(tdRisk);

        // 8. Incident ID / Details Cell
        const tdIncident = document.createElement("td");
        tdIncident.className = "incident-link-cell";
        if (post.incident_id) {
            const link = document.createElement("a");
            link.className = "incident-link";
            link.href = `/incidents/${encodeURIComponent(post.incident_id)}`;
            link.textContent = post.incident_id;
            link.target = "_blank";
            tdIncident.appendChild(link);
        } else {
            tdIncident.textContent = "-";
        }
        tr.appendChild(tdIncident);

        return tr;
    }

    function renderFeedRows() {
        if (!liveFeedBody) return;

        // Clear existing rows
        liveFeedBody.replaceChildren();

        const filtered = feedEvents.filter((item) => {
            if (currentSourceFilter === "all") return true;
            return String(item.source || "").toLowerCase() === currentSourceFilter;
        });

        if (filtered.length === 0) {
            const tr = document.createElement("tr");
            const td = document.createElement("td");
            td.colSpan = 8;
            td.className = "empty-state-cell";

            const wrap = document.createElement("div");
            wrap.className = "empty-state-wrap";

            const icon = document.createElement("span");
            icon.className = "empty-icon";
            icon.textContent = "📡";

            const text = document.createElement("p");
            text.className = "empty-text";
            text.textContent = `No live events recorded for '${currentSourceFilter.toUpperCase()}' yet.`;

            wrap.appendChild(icon);
            wrap.appendChild(text);
            td.appendChild(wrap);
            tr.appendChild(td);
            liveFeedBody.appendChild(tr);
            return;
        }

        filtered.forEach((post) => {
            liveFeedBody.appendChild(createFeedRow(post, false));
        });
    }

    function addFeedEvent(post, isNew = true) {
        if (!post || typeof post !== "object") return;

        // Extract identifiers for strict deduplication
        const postId = post.id !== undefined && post.id !== null ? String(post.id) : null;
        const sourceKey = post.source && post.source_id ? `${post.source}:${post.source_id}` : null;
        const incidentId = post.incident_id ? String(post.incident_id) : null;

        // Check if event already exists by database ID, (source + source_id), or incident_id
        const existingIdx = feedEvents.findIndex((e) => {
            if (postId && e.id !== undefined && e.id !== null && String(e.id) === postId) return true;
            if (sourceKey && e.source && e.source_id && `${e.source}:${e.source_id}` === sourceKey) return true;
            if (incidentId && e.incident_id && String(e.incident_id) === incidentId) return true;
            return false;
        });

        if (existingIdx >= 0) {
            // Update in-place to avoid duplicate rows
            feedEvents[existingIdx] = Object.assign({}, feedEvents[existingIdx], post);
            renderFeedRows();
            return;
        }

        // Prepend new unique event to front of feed
        feedEvents.unshift(post);
        if (feedEvents.length > MAX_FEED_ROWS) {
            feedEvents.pop();
        }

        renderFeedRows();
    }

    // --- Real-time Transport: Server-Sent Events (SSE) ---

    function startSSE() {
        if (eventSource) {
            eventSource.close();
        }

        streamPulse.className = "pulse-indicator";
        streamStatusText.textContent = "CONNECTING TO LIVE STREAM (SSE)...";

        try {
            eventSource = new EventSource("/api/live/events");

            eventSource.addEventListener("open", () => {
                isPollingFallback = false;
                if (pollIntervalId) {
                    clearInterval(pollIntervalId);
                    pollIntervalId = null;
                }
                streamPulse.className = "pulse-indicator";
                streamStatusText.textContent = "LIVE STREAMING (SSE ACTIVE)";
            });

            // Initial State Snapshot
            eventSource.addEventListener("initial_state", (e) => {
                try {
                    const data = JSON.parse(e.data);
                    updateMetrics(data);
                    updateConnectorCards(data.connector_states, data);

                    if (Array.isArray(data.recent_events)) {
                        data.recent_events.forEach((ev) => {
                            if (ev.type === "incident_alert") {
                                // Show latest incident alert in top banner if available
                                if (ev.data) showAlert(ev.data);
                                return;
                            }
                            const postData = ev.data || ev;
                            addFeedEvent(postData, false);
                        });
                    }
                } catch (err) {
                    console.error("Error parsing initial_state event:", err);
                }
            });

            // Incoming Source Post Event
            eventSource.addEventListener("source_post", (e) => {
                try {
                    const payload = JSON.parse(e.data);
                    const post = payload.data || payload;
                    addFeedEvent(post, true);

                    // Increment analyzed count on UI
                    const currentCount = parseInt(metricAnalyzed.textContent || "0", 10);
                    metricAnalyzed.textContent = String(currentCount + 1);
                } catch (err) {
                    console.error("Error parsing source_post event:", err);
                }
            });

            // Incident Alert Event (Popup banner only)
            eventSource.addEventListener("incident_alert", (e) => {
                try {
                    const payload = JSON.parse(e.data);
                    const alertData = payload.data || payload;
                    showAlert(alertData);

                    // Increment incident count on UI
                    const currentCount = parseInt(metricIncidents.textContent || "0", 10);
                    metricIncidents.textContent = String(currentCount + 1);
                } catch (err) {
                    console.error("Error parsing incident_alert event:", err);
                }
            });

            // Error & Fallback Handler
            eventSource.addEventListener("error", () => {
                console.warn("SSE connection encountered an error or disconnected. Activating polling fallback.");
                if (eventSource) {
                    eventSource.close();
                    eventSource = null;
                }
                startPollingFallback();
            });
        } catch (err) {
            console.error("Failed to initialize EventSource:", err);
            startPollingFallback();
        }
    }

    // --- Polling Fallback ---

    function startPollingFallback() {
        if (isPollingFallback) return;
        isPollingFallback = true;

        streamPulse.className = "pulse-indicator polling";
        streamStatusText.textContent = "POLLING ACTIVE (FALLBACK)";

        pollLiveData();
        pollIntervalId = setInterval(pollLiveData, 3000);
    }

    async function pollLiveData() {
        try {
            // Fetch live status
            const statusRes = await fetch("/api/live/status");
            if (statusRes.ok) {
                const statusJson = await statusRes.json();
                if (statusJson.success && statusJson.live_status) {
                    const ls = statusJson.live_status;
                    updateMetrics(ls);
                    updateConnectorCards(ls.connector_states, ls);
                    if (subscribersCountBadge) {
                        subscribersCountBadge.textContent = `${ls.active_subscribers} active listeners`;
                    }
                }
            }

            // Fetch live feed
            const feedRes = await fetch(`/api/live/feed?source=${encodeURIComponent(currentSourceFilter)}&limit=50`);
            if (feedRes.ok) {
                const feedJson = await feedRes.json();
                if (feedJson.success && Array.isArray(feedJson.events)) {
                    feedJson.events.forEach((ev) => {
                        if (ev.type === "incident_alert") {
                            return; // Alert popups are handled separately
                        }
                        const post = ev.data || ev;
                        addFeedEvent(post, false);
                    });
                }
            }
        } catch (err) {
            console.warn("Polling error:", err);
            streamPulse.className = "pulse-indicator disconnected";
            streamStatusText.textContent = "DISCONNECTED";
        }
    }

    // Start Live Stream Connection
    startSSE();
});
