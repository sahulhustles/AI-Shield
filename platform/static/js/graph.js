/**
 * AIShield - Threat Relationship Graph & Campaign Detection Client Logic (Module 5)
 */

document.addEventListener("DOMContentLoaded", () => {
    let networkInstance = null;

    // DOM Elements
    const thresholdSlider = document.getElementById("threshold-slider");
    const thresholdValDisplay = document.getElementById("threshold-val");
    const btnReanalyzeGraph = document.getElementById("btn-reanalyze-graph");
    const graphSpinner = document.getElementById("graph-spinner");
    const btnGraphLabel = document.getElementById("btn-graph-label");

    const metricNodeCount = document.getElementById("metric-node-count");
    const metricEdgeCount = document.getElementById("metric-edge-count");
    const metricClusterCount = document.getElementById("metric-cluster-count");
    const metricCampaignCount = document.getElementById("metric-campaign-count");

    const graphContainer = document.getElementById("graph-network");
    const graphErrorBanner = document.getElementById("graph-error-banner");
    const graphErrorMessage = document.getElementById("graph-error-message");
    const graphStatusBanner = document.getElementById("graph-status-banner");
    const graphStatusText = document.getElementById("graph-status-text");

    const inspectorPlaceholder = document.getElementById("inspector-placeholder");
    const inspectorDetails = document.getElementById("inspector-details");

    const inspId = document.getElementById("insp-id");
    const inspCategory = document.getElementById("insp-category");
    const inspRisk = document.getElementById("insp-risk");
    const inspScore = document.getElementById("insp-score");
    const inspAiProb = document.getElementById("insp-ai-prob");
    const inspCreated = document.getElementById("insp-created");
    const inspViewLink = document.getElementById("insp-view-link");

    const campaignsTbody = document.getElementById("campaigns-tbody");

    // Color mapping for risk levels (warm professional palette)
    const RISK_COLORS = {
        CRITICAL: { background: "#b91c1c", border: "#991b1b" },
        HIGH: { background: "#c2410c", border: "#9a3412" },
        MEDIUM: { background: "#b45309", border: "#92400e" },
        LOW: { background: "#15803d", border: "#166534" },
    };

    function setStatusBanner(msg) {
        if (!graphStatusBanner || !graphStatusText) return;
        if (msg) {
            graphStatusText.textContent = msg;
            graphStatusBanner.style.display = "flex";
        } else {
            graphStatusBanner.style.display = "none";
        }
    }

    // =========================================================================
    // 1. Slider Event Handler
    // =========================================================================
    if (thresholdSlider && thresholdValDisplay) {
        thresholdSlider.addEventListener("input", (e) => {
            thresholdValDisplay.textContent = Number(e.target.value).toFixed(2);
        });
    }

    // =========================================================================
    // 2. Fetch and Render Relationship Graph
    // =========================================================================
    async function loadGraphData() {
        const threshold = thresholdSlider ? Number(thresholdSlider.value).toFixed(2) : "0.65";

        if (btnReanalyzeGraph) btnReanalyzeGraph.disabled = true;
        if (graphSpinner) graphSpinner.style.display = "inline-block";
        if (btnGraphLabel) btnGraphLabel.textContent = "Analyzing...";
        if (graphErrorBanner) graphErrorBanner.style.display = "none";

        try {
            const resp = await fetch(`/api/graph?threshold=${encodeURIComponent(threshold)}`);
            const data = await resp.json();

            if (!resp.ok || !data.success) {
                renderGraphMessage("Failed to generate relationship graph.");
                if (graphErrorBanner && graphErrorMessage) {
                    graphErrorMessage.textContent = data.error || "An error occurred generating the relationship graph.";
                    graphErrorBanner.style.display = "flex";
                }
                return;
            }

            // 1. Update Metrics Bar
            const sum = data.summary || { incident_count: 0, edge_count: 0, cluster_count: 0, campaign_count: 0 };
            if (metricNodeCount) metricNodeCount.textContent = String(sum.incident_count || 0);
            if (metricEdgeCount) metricEdgeCount.textContent = String(sum.edge_count || 0);
            if (metricClusterCount) metricClusterCount.textContent = String(sum.cluster_count || 0);
            if (metricCampaignCount) metricCampaignCount.textContent = String(sum.campaign_count || 0);

            // 2. Render Network Graph
            renderVisNetwork(data.nodes || [], data.edges || []);

            // 3. Render Potential Campaigns Table
            renderCampaignsTable(data.campaigns || []);

        } catch (err) {
            console.error("Error loading graph:", err);
            renderGraphMessage("Unable to connect to server. Please check your connection.");
            if (graphErrorBanner && graphErrorMessage) {
                graphErrorMessage.textContent = "Unable to connect to graph API server.";
                graphErrorBanner.style.display = "flex";
            }
        } finally {
            if (btnReanalyzeGraph) btnReanalyzeGraph.disabled = false;
            if (graphSpinner) graphSpinner.style.display = "none";
            if (btnGraphLabel) btnGraphLabel.textContent = "Analyze Relationships";
        }
    }

    function renderGraphMessage(msg) {
        if (!graphContainer) return;
        while (graphContainer.firstChild) graphContainer.removeChild(graphContainer.firstChild);
        const p = document.createElement("p");
        p.className = "graph-empty-message";
        p.textContent = msg;
        graphContainer.appendChild(p);
    }

    // =========================================================================
    // 3. vis-network Rendering Engine
    // =========================================================================
    function renderVisNetwork(nodesData, edgesData) {
        if (!graphContainer) return;

        // Case 1: 0 incidents
        if (nodesData.length === 0) {
            if (networkInstance) {
                networkInstance.destroy();
                networkInstance = null;
            }
            setStatusBanner("Limited incident data available for graph analysis.");
            renderGraphMessage("No incidents available for graph analysis.");
            hideNodeDetails();
            return;
        }

        // Case 2: 1 incident
        if (nodesData.length === 1) {
            setStatusBanner("At least 2 incidents are required to build relationships.");
        } else if (edgesData.length === 0) {
            // Case 3: 2+ incidents, 0 edges meet threshold
            setStatusBanner("Incidents found, but no relationships meet the current similarity threshold.");
        } else {
            // Case 4: 2+ incidents with relationship edges
            if (nodesData.length <= 2) {
                setStatusBanner("Limited incident data available for graph analysis.");
            } else {
                setStatusBanner(null);
            }
        }

        // Check library availability
        if (typeof vis === "undefined" || !vis.Network) {
            renderGraphMessage("Graph visualization library (vis-network) failed to load. Please check network connection.");
            return;
        }

        while (graphContainer.firstChild) graphContainer.removeChild(graphContainer.firstChild);

        // Format nodes for vis-network
        const visNodes = nodesData.map((node) => {
            const rLevel = (node.risk_level || "LOW").toUpperCase();
            const colorTheme = RISK_COLORS[rLevel] || RISK_COLORS.LOW;
            const shortId = node.id.length > 12 ? `${node.id.substring(0, 7)}...` : node.id;

            return {
                id: node.id,
                label: shortId,
                title: `${node.id} | ${node.category} (${rLevel}, Threat Score: ${node.threat_score})`,
                color: {
                    background: colorTheme.background,
                    border: colorTheme.border,
                    highlight: { background: "#ffffff", border: colorTheme.background },
                },
                font: { color: "#1c1917", size: 11, face: "Inter" },
                shape: "dot",
                size: Math.max(12, Math.min(26, 10 + (Number(node.threat_score) / 6))),
                borderWidth: 2,
                raw_node: node,
            };
        });

        // Format edges for vis-network with dynamic elasticity
        const visEdges = edgesData.map((edge) => {
            const sim = Number(edge.similarity);
            const width = Math.max(1.5, Math.min(6, (sim - 0.4) * 8));
            // Elastic spring distance: higher similarity items pull closer together
            const length = Math.max(45, Math.min(180, (1.05 - sim) * 220));

            return {
                from: edge.source,
                to: edge.target,
                title: `Similarity: ${(sim * 100).toFixed(1)}%`,
                width: width,
                length: length,
                color: { color: "rgba(120, 113, 108, 0.45)", highlight: "#c2410c" },
                smooth: { type: "continuous" },
            };
        });

        const data = {
            nodes: new vis.DataSet(visNodes),
            edges: new vis.DataSet(visEdges),
        };

        const options = {
            autoResize: true,
            height: "100%",
            width: "100%",
            physics: {
                solver: "forceAtlas2Based",
                forceAtlas2Based: {
                    gravitationalConstant: -38,
                    centralGravity: 0.008,
                    springLength: 90,
                    springConstant: 0.08,
                    damping: 0.45,
                    avoidOverlap: 0.6,
                },
                stabilization: {
                    enabled: true,
                    iterations: 100,
                    updateInterval: 25,
                    fit: true,
                },
                maxVelocity: 35,
                minVelocity: 0.75,
            },
            interaction: {
                hover: true,
                tooltipDelay: 100,
                zoomView: true,
                dragView: true,
            },
        };

        if (networkInstance) {
            networkInstance.destroy();
            networkInstance = null;
        }

        networkInstance = new vis.Network(graphContainer, data, options);

        // Handle Node Selection for Inspector Drawer
        networkInstance.on("selectNode", (params) => {
            if (params.nodes.length > 0) {
                const selectedId = params.nodes[0];
                const nodeObj = nodesData.find((n) => n.id === selectedId);
                if (nodeObj) {
                    showNodeDetails(nodeObj);
                }
            }
        });

        networkInstance.on("deselectNode", () => {
            hideNodeDetails();
        });
    }

    // =========================================================================
    // 4. Node Inspector Controller (Safe DOM Rendering)
    // =========================================================================
    function showNodeDetails(node) {
        if (inspectorPlaceholder) inspectorPlaceholder.style.display = "none";
        if (inspectorDetails) inspectorDetails.style.display = "flex";

        if (inspId) inspId.textContent = node.id;
        if (inspCategory) inspCategory.textContent = node.category;
        if (inspRisk) {
            const rLevel = (node.risk_level || "LOW").toUpperCase();
            inspRisk.className = `risk-badge risk-${rLevel.toLowerCase()}`;
            inspRisk.textContent = rLevel;
        }
        if (inspScore) inspScore.textContent = `${Number(node.threat_score).toFixed(1)} / 100`;
        if (inspAiProb) inspAiProb.textContent = `${(Number(node.ai_probability) * 100).toFixed(1)}% (${node.ai_label})`;
        if (inspCreated) {
            const dt = new Date(node.created_at);
            inspCreated.textContent = isNaN(dt.getTime())
                ? node.created_at
                : dt.toISOString().replace("T", " ").substring(0, 19) + " UTC";
        }
        if (inspViewLink) {
            inspViewLink.href = `/incidents/${encodeURIComponent(node.id)}`;
        }
    }

    function hideNodeDetails() {
        if (inspectorPlaceholder) inspectorPlaceholder.style.display = "flex";
        if (inspectorDetails) inspectorDetails.style.display = "none";
    }

    // =========================================================================
    // 5. Campaigns Table Renderer
    // =========================================================================
    function renderCampaignsTable(campaigns) {
        if (!campaignsTbody) return;

        while (campaignsTbody.firstChild) {
            campaignsTbody.removeChild(campaignsTbody.firstChild);
        }

        if (campaigns.length === 0) {
            const tr = document.createElement("tr");
            const td = document.createElement("td");
            td.colSpan = 10;
            td.className = "table-empty-message";
            td.textContent = "No potential campaigns detected at the current similarity threshold.";
            tr.appendChild(td);
            campaignsTbody.appendChild(tr);
            return;
        }

        campaigns.forEach((camp) => {
            const tr = document.createElement("tr");

            // Campaign ID
            const tdId = document.createElement("td");
            const tag = document.createElement("span");
            tag.className = "campaign-tag";
            tag.textContent = camp.campaign_id;
            tdId.appendChild(tag);

            // Incidents Count
            const tdCount = document.createElement("td");
            tdCount.className = "font-mono";
            tdCount.textContent = `${camp.incident_count} incidents`;

            // Risk Level
            const tdRisk = document.createElement("td");
            const rBadge = document.createElement("span");
            const rLvl = (camp.risk_level || "LOW").toUpperCase();
            rBadge.className = `risk-badge risk-${rLvl.toLowerCase()}`;
            rBadge.style.fontSize = "0.75rem";
            rBadge.style.padding = "0.2rem 0.55rem";
            rBadge.textContent = rLvl;
            tdRisk.appendChild(rBadge);

            // Campaign Risk Score
            const tdScore = document.createElement("td");
            tdScore.className = "font-mono";
            tdScore.textContent = `${Number(camp.campaign_risk_score).toFixed(1)}`;

            // Avg Similarity
            const tdSim = document.createElement("td");
            tdSim.className = "font-mono";
            tdSim.textContent = `${(Number(camp.average_similarity) * 100).toFixed(1)}%`;

            // Avg AI Probability
            const tdAi = document.createElement("td");
            tdAi.className = "font-mono";
            tdAi.textContent = `${(Number(camp.average_ai_probability) * 100).toFixed(1)}%`;

            // Avg Threat Score
            const tdThreat = document.createElement("td");
            tdThreat.className = "font-mono";
            tdThreat.textContent = `${Number(camp.average_threat_score).toFixed(1)}`;

            // Primary Category
            const tdCat = document.createElement("td");
            const catBadge = document.createElement("span");
            catBadge.className = "badge badge-category";
            catBadge.textContent = camp.primary_category;
            tdCat.appendChild(catBadge);

            // Time Range / Duration
            const tdTime = document.createElement("td");
            tdTime.className = "font-mono";
            tdTime.textContent = `${camp.duration_hours}h span`;

            // View Related Incidents Action (Pill links)
            const tdAction = document.createElement("td");
            const pillList = document.createElement("div");
            pillList.className = "incident-pill-list";

            (camp.incident_ids || []).forEach((incId) => {
                const a = document.createElement("a");
                a.className = "inc-pill";
                a.href = `/incidents/${encodeURIComponent(incId)}`;
                a.textContent = incId.length > 10 ? `${incId.substring(0, 7)}...` : incId;
                a.title = `View incident ${incId}`;
                pillList.appendChild(a);
            });
            tdAction.appendChild(pillList);

            tr.appendChild(tdId);
            tr.appendChild(tdCount);
            tr.appendChild(tdRisk);
            tr.appendChild(tdScore);
            tr.appendChild(tdSim);
            tr.appendChild(tdAi);
            tr.appendChild(tdThreat);
            tr.appendChild(tdCat);
            tr.appendChild(tdTime);
            tr.appendChild(tdAction);

            campaignsTbody.appendChild(tr);
        });
    }

    // =========================================================================
    // 6. GNN Threat Cluster Analysis Controller
    // =========================================================================

    const gnnStatusBadge = document.getElementById("gnn-status-badge");
    const gnnMetaStatus = document.getElementById("gnn-meta-status");
    const gnnMetaVersion = document.getElementById("gnn-meta-version");
    const gnnMetaNodes = document.getElementById("gnn-meta-nodes");
    const gnnMetaEdges = document.getElementById("gnn-meta-edges");
    const gnnMetaEval = document.getElementById("gnn-meta-eval");

    const btnGnnTrain = document.getElementById("btn-gnn-train");
    const gnnTrainSpinner = document.getElementById("gnn-train-spinner");
    const btnGnnTrainLabel = document.getElementById("btn-gnn-train-label");

    const btnGnnPredict = document.getElementById("btn-gnn-predict");
    const gnnPredictSpinner = document.getElementById("gnn-predict-spinner");
    const btnGnnPredictLabel = document.getElementById("btn-gnn-predict-label");

    const gnnPredictionsTbody = document.getElementById("gnn-predictions-tbody");

    async function loadGnnStatus() {
        try {
            const resp = await fetch("/api/gnn/status");
            const data = await resp.json();
            if (!resp.ok || !data.success) return;

            const st = (data.status || "INSUFFICIENT_DATA").toUpperCase();
            if (gnnStatusBadge) {
                gnnStatusBadge.textContent = st;
                gnnStatusBadge.className = `gnn-badge-status ${st === "READY" ? "badge-connected" : "badge-disabled"}`;
            }
            if (gnnMetaStatus) gnnMetaStatus.textContent = st;
            if (gnnMetaVersion) gnnMetaVersion.textContent = data.model_version || "v1.0.0";
            if (gnnMetaNodes) gnnMetaNodes.textContent = String(data.training_node_count || 0);
            if (gnnMetaEdges) gnnMetaEdges.textContent = String(data.training_edge_count || 0);
            if (gnnMetaEval) {
                gnnMetaEval.textContent = data.evaluation_status || "INSUFFICIENT_DATA";
            }
        } catch (err) {
            console.error("Error loading GNN status:", err);
        }
    }

    async function loadGnnPredictions() {
        const threshold = thresholdSlider ? Number(thresholdSlider.value).toFixed(2) : "0.65";
        try {
            const resp = await fetch(`/api/gnn/predictions?threshold=${encodeURIComponent(threshold)}`);
            const data = await resp.json();
            if (!resp.ok || !data.success) {
                renderGnnEmptyState("Failed to load GNN predictions.");
                return;
            }

            if (data.status === "NOT_TRAINED") {
                renderGnnEmptyState("GNN model is not trained yet. Click 'Train GNN Model' above.");
                return;
            } else if (data.status === "NO_DATA") {
                renderGnnEmptyState("No incidents available for GNN cluster analysis.");
                return;
            }

            renderGnnPredictionsTable(data.predictions || []);
        } catch (err) {
            console.error("Error loading GNN predictions:", err);
            renderGnnEmptyState("Unable to connect to GNN API.");
        }
    }

    function renderGnnEmptyState(msg) {
        if (!gnnPredictionsTbody) return;
        while (gnnPredictionsTbody.firstChild) {
            gnnPredictionsTbody.removeChild(gnnPredictionsTbody.firstChild);
        }
        const tr = document.createElement("tr");
        const td = document.createElement("td");
        td.colSpan = 8;
        td.className = "table-empty-message";
        td.textContent = msg;
        tr.appendChild(td);
        gnnPredictionsTbody.appendChild(tr);
    }

    function renderGnnPredictionsTable(predictions) {
        if (!gnnPredictionsTbody) return;
        while (gnnPredictionsTbody.firstChild) {
            gnnPredictionsTbody.removeChild(gnnPredictionsTbody.firstChild);
        }

        if (predictions.length === 0) {
            renderGnnEmptyState("No predictions returned for the current incident graph.");
            return;
        }

        predictions.forEach((pred) => {
            const tr = document.createElement("tr");

            // 1. Incident ID
            const tdId = document.createElement("td");
            const aId = document.createElement("a");
            aId.className = "font-mono font-bold text-primary";
            aId.href = `/incidents/${encodeURIComponent(pred.incident_id)}`;
            aId.textContent = pred.incident_id.length > 12 ? `${pred.incident_id.substring(0, 8)}...` : pred.incident_id;
            aId.title = `View incident ${pred.incident_id}`;
            tdId.appendChild(aId);

            // 2. Cluster Probability Bar
            const tdProb = document.createElement("td");
            const probContainer = document.createElement("div");
            probContainer.className = "prob-cell-container";

            const probText = document.createElement("span");
            probText.className = "font-mono font-bold";
            probText.textContent = `${(Number(pred.cluster_membership_probability) * 100).toFixed(1)}%`;

            const probTrack = document.createElement("div");
            probTrack.className = "prob-bar-track";
            const probFill = document.createElement("div");
            const probVal = Number(pred.cluster_membership_probability) * 100;
            probFill.className = `prob-bar-fill ${probVal >= 70 ? "fill-high" : probVal >= 40 ? "fill-possible" : "fill-low"}`;
            probFill.style.width = `${Math.max(4, Math.min(100, probVal))}%`;
            probTrack.appendChild(probFill);

            probContainer.appendChild(probText);
            probContainer.appendChild(probTrack);
            tdProb.appendChild(probContainer);

            // 3. Classification Badge
            const tdClass = document.createElement("td");
            const badge = document.createElement("span");
            const cls = pred.classification || "LOW_LIKELIHOOD";
            if (cls === "HIGH_LIKELIHOOD") {
                badge.className = "badge-likelihood-high";
                badge.textContent = "HIGH LIKELIHOOD";
            } else if (cls === "POSSIBLE") {
                badge.className = "badge-likelihood-possible";
                badge.textContent = "POSSIBLE";
            } else {
                badge.className = "badge-likelihood-low";
                badge.textContent = "LOW LIKELIHOOD";
            }
            tdClass.appendChild(badge);

            // 4. Neighbors Count
            const tdNeigh = document.createElement("td");
            tdNeigh.className = "font-mono text-center";
            tdNeigh.textContent = String(pred.explanation?.neighbor_count ?? 0);

            // 5. Avg Similarity
            const tdSim = document.createElement("td");
            tdSim.className = "font-mono text-center";
            const avgSim = Number(pred.explanation?.average_neighbor_similarity || 0) * 100;
            tdSim.textContent = `${avgSim.toFixed(1)}%`;

            // 6. Avg Neighbor Threat
            const tdThreat = document.createElement("td");
            tdThreat.className = "font-mono text-center";
            tdThreat.textContent = `${Number(pred.explanation?.average_neighbor_threat_score || 0).toFixed(1)}`;

            // 7. Cluster Size
            const tdCluster = document.createElement("td");
            tdCluster.className = "font-mono text-center";
            tdCluster.textContent = String(pred.explanation?.cluster_size ?? 1);

            // 8. Action link
            const tdAction = document.createElement("td");
            const btnView = document.createElement("a");
            btnView.className = "inc-pill";
            btnView.href = `/incidents/${encodeURIComponent(pred.incident_id)}`;
            btnView.textContent = "Inspect";
            tdAction.appendChild(btnView);

            tr.appendChild(tdId);
            tr.appendChild(tdProb);
            tr.appendChild(tdClass);
            tr.appendChild(tdNeigh);
            tr.appendChild(tdSim);
            tr.appendChild(tdThreat);
            tr.appendChild(tdCluster);
            tr.appendChild(tdAction);

            gnnPredictionsTbody.appendChild(tr);
        });
    }

    // GNN Action Event Listeners
    if (btnGnnTrain) {
        btnGnnTrain.addEventListener("click", async () => {
            const threshold = thresholdSlider ? Number(thresholdSlider.value).toFixed(2) : "0.65";
            btnGnnTrain.disabled = true;
            if (gnnTrainSpinner) gnnTrainSpinner.style.display = "inline-block";
            if (btnGnnTrainLabel) btnGnnTrainLabel.textContent = "Training GNN...";

            try {
                const resp = await fetch("/api/gnn/train", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ threshold: Number(threshold) }),
                });
                const data = await resp.json();
                await loadGnnStatus();
                await loadGnnPredictions();

                if (data.training_status === "INSUFFICIENT_DATA") {
                    alert(`GNN Training Notice: ${data.message || "Insufficient incident data to train GNN."}`);
                }
            } catch (err) {
                console.error("GNN Training error:", err);
            } finally {
                btnGnnTrain.disabled = false;
                if (gnnTrainSpinner) gnnTrainSpinner.style.display = "none";
                if (btnGnnTrainLabel) btnGnnTrainLabel.textContent = "Train GNN Model";
            }
        });
    }

    if (btnGnnPredict) {
        btnGnnPredict.addEventListener("click", async () => {
            btnGnnPredict.disabled = true;
            if (gnnPredictSpinner) gnnPredictSpinner.style.display = "inline-block";
            if (btnGnnPredictLabel) btnGnnPredictLabel.textContent = "Analyzing...";

            try {
                await loadGnnPredictions();
                await loadGnnStatus();
            } finally {
                btnGnnPredict.disabled = false;
                if (gnnPredictSpinner) gnnPredictSpinner.style.display = "none";
                if (btnGnnPredictLabel) btnGnnPredictLabel.textContent = "Run GNN Analysis";
            }
        });
    }

    // Auto-Refresh Controller (8s Live Poll)
    const btnToggleAutoRefresh = document.getElementById("btn-toggle-auto-refresh");
    const autoRefreshState = document.getElementById("auto-refresh-state");
    let autoRefreshEnabled = true;
    let autoRefreshTimer = null;
    let lastRenderedNodeIds = "";

    function toggleAutoRefresh() {
        autoRefreshEnabled = !autoRefreshEnabled;
        if (autoRefreshState) {
            autoRefreshState.textContent = autoRefreshEnabled ? "ON (8s)" : "PAUSED";
            autoRefreshState.style.color = autoRefreshEnabled ? "var(--accent)" : "var(--text-muted)";
        }
        if (btnToggleAutoRefresh) {
            btnToggleAutoRefresh.classList.toggle("active", autoRefreshEnabled);
        }
    }

    if (btnToggleAutoRefresh) {
        btnToggleAutoRefresh.addEventListener("click", toggleAutoRefresh);
    }

    // Auto-poll loop for real-time live monitoring synchronization
    function startAutoRefreshLoop() {
        if (autoRefreshTimer) clearInterval(autoRefreshTimer);
        autoRefreshTimer = setInterval(async () => {
            if (!autoRefreshEnabled || document.hidden) return;
            // Background silent refresh for live updates
            const threshold = thresholdSlider ? Number(thresholdSlider.value).toFixed(2) : "0.65";
            try {
                const resp = await fetch(`/api/graph?threshold=${encodeURIComponent(threshold)}&limit=50`);
                const data = await resp.json();
                if (data && data.success) {
                    const currentIds = (data.nodes || []).map(n => n.id).sort().join(",");
                    if (currentIds !== lastRenderedNodeIds) {
                        // Node set changed from live ingestion, re-render
                        lastRenderedNodeIds = currentIds;
                        const sum = data.summary || { incident_count: 0, edge_count: 0, cluster_count: 0, campaign_count: 0 };
                        if (metricNodeCount) metricNodeCount.textContent = String(sum.incident_count || 0);
                        if (metricEdgeCount) metricEdgeCount.textContent = String(sum.edge_count || 0);
                        if (metricClusterCount) metricClusterCount.textContent = String(sum.cluster_count || 0);
                        if (metricCampaignCount) metricCampaignCount.textContent = String(sum.campaign_count || 0);
                        renderVisNetwork(data.nodes || [], data.edges || []);
                        renderCampaignsTable(data.campaigns || []);
                    }
                }
            } catch (err) {
                // Silently ignore background poll errors
            }
        }, 8000);
    }

    if (btnReanalyzeGraph) {
        btnReanalyzeGraph.addEventListener("click", () => {
            loadGraphData();
            loadGnnStatus();
            loadGnnPredictions();
        });
    }

    // Initial Graph & GNN Load
    loadGraphData();
    loadGnnStatus();
    loadGnnPredictions();
    startAutoRefreshLoop();
});
