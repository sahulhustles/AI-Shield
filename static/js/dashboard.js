/**
 * AIShield - Threat Intelligence Dashboard Client Logic (Module 4)
 * Provides asynchronous data loading, Chart.js visualizations, and multi-filter search.
 */

document.addEventListener("DOMContentLoaded", () => {
    // Chart instances registry (to cleanly recreate on refresh)
    const chartInstances = {};

    // Pagination and filter state
    let currentPage = 1;
    const pageSize = 20;

    // DOM element references
    const searchForm = document.getElementById("dashboard-filter-form");
    const btnApplyFilters = document.getElementById("btn-apply-filters");
    const btnResetFilters = document.getElementById("btn-reset-filters");
    const searchResultsTbody = document.getElementById("search-results-tbody");
    const paginationBar = document.getElementById("pagination-bar");
    const paginationInfo = document.getElementById("pagination-info");
    const pageIndicator = document.getElementById("page-indicator");
    const btnPrevPage = document.getElementById("btn-prev-page");
    const btnNextPage = document.getElementById("btn-next-page");
    const searchErrorBanner = document.getElementById("search-error-banner");
    const searchErrorMessage = document.getElementById("search-error-message");

    // =========================================================================
    // 1. Helper: Render Table Row for Incident Summaries
    // =========================================================================
    function createIncidentTableRow(inc) {
        const tr = document.createElement("tr");

        // Incident ID
        const tdId = document.createElement("td");
        const idSpan = document.createElement("span");
        idSpan.className = "id-tag";
        idSpan.textContent = inc.incident_id;
        tdId.appendChild(idSpan);

        // Date (UTC)
        const tdTime = document.createElement("td");
        tdTime.className = "font-mono";
        const dt = new Date(inc.created_at);
        tdTime.textContent = isNaN(dt.getTime())
            ? inc.created_at
            : dt.toISOString().replace("T", " ").substring(0, 19) + " UTC";

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
        tdScore.textContent = Number(inc.threat_score).toFixed(1);

        // AI Prob
        const tdAi = document.createElement("td");
        tdAi.className = "font-mono";
        tdAi.textContent = `${(Number(inc.ai_probability) * 100).toFixed(1)}%`;

        // SHA-256 Hash
        const tdHash = document.createElement("td");
        const hashSpan = document.createElement("span");
        hashSpan.className = "hash-preview";
        const h = inc.content_hash || "";
        hashSpan.textContent = h.length > 12 ? `${h.substring(0, 6)}...${h.substring(h.length - 6)}` : h;
        hashSpan.title = h;
        tdHash.appendChild(hashSpan);

        // Action
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

        return tr;
    }

    function renderEmptyRow(tbody, message) {
        while (tbody.firstChild) {
            tbody.removeChild(tbody.firstChild);
        }
        const tr = document.createElement("tr");
        const td = document.createElement("td");
        td.colSpan = 8;
        td.className = "table-empty-message";
        td.textContent = message;
        tr.appendChild(td);
        tbody.appendChild(tr);
    }

    // =========================================================================
    // 2. Summary Statistics Loader
    // =========================================================================
    async function loadSummaryStats() {
        try {
            const resp = await fetch("/api/dashboard/summary");
            const data = await resp.json();
            if (resp.ok && data.success && data.summary) {
                const s = data.summary;
                document.getElementById("stat-total").textContent = Number(s.total_incidents).toLocaleString();
                document.getElementById("stat-high").textContent = Number(s.high_risk).toLocaleString();
                document.getElementById("stat-critical").textContent = Number(s.critical_risk).toLocaleString();
                document.getElementById("stat-ai").textContent = Number(s.ai_generated).toLocaleString();
                document.getElementById("stat-human").textContent = Number(s.human).toLocaleString();
                document.getElementById("stat-avg-score").textContent = Number(s.average_threat_score).toFixed(1);
            }
        } catch (err) {
            console.error("Failed to load summary statistics:", err);
        }
    }

    // =========================================================================
    // 3. Analytics Charts Loader
    // =========================================================================
    async function loadCharts() {
        if (typeof Chart === "undefined") {
            console.warn("Chart.js is not loaded.");
            return;
        }

        Chart.defaults.color = "#57534e";
        Chart.defaults.borderColor = "#e5e0d8";
        Chart.defaults.font.family = "'Inter', ui-sans-serif, system-ui, sans-serif";

        try {
            // Fetch Distributions
            const distResp = await fetch("/api/dashboard/distribution");
            const distData = await distResp.json();

            if (distResp.ok && distData.success) {
                // 1. Risk Level Chart (Doughnut)
                const ctxRisk = document.getElementById("chart-risk");
                if (ctxRisk) {
                    if (chartInstances.risk) chartInstances.risk.destroy();
                    const riskObj = distData.risk || {};
                    chartInstances.risk = new Chart(ctxRisk, {
                        type: "doughnut",
                        data: {
                            labels: ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                            datasets: [{
                                data: [
                                    riskObj.LOW || 0,
                                    riskObj.MEDIUM || 0,
                                    riskObj.HIGH || 0,
                                    riskObj.CRITICAL || 0,
                                ],
                                backgroundColor: ["#15803d", "#b45309", "#c2410c", "#b91c1c"],
                                borderWidth: 0,
                            }],
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            plugins: {
                                legend: { position: "bottom" },
                            },
                        },
                    });
                }

                // 2. Category Distribution Chart (Bar)
                const ctxCat = document.getElementById("chart-category");
                if (ctxCat) {
                    if (chartInstances.category) chartInstances.category.destroy();
                    const catObj = distData.categories || {};
                    const catLabels = Object.keys(catObj);
                    const catValues = Object.values(catObj);

                    chartInstances.category = new Chart(ctxCat, {
                        type: "bar",
                        data: {
                            labels: catLabels,
                            datasets: [{
                                label: "Incidents",
                                data: catValues,
                                backgroundColor: "rgba(194, 65, 12, 0.75)",
                                borderRadius: 4,
                            }],
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            plugins: {
                                legend: { display: false },
                            },
                            scales: {
                                y: {
                                    beginAtZero: true,
                                    ticks: { precision: 0 },
                                },
                            },
                        },
                    });
                }

                // 3. AI vs Human Distribution (Pie)
                const ctxAi = document.getElementById("chart-ai");
                if (ctxAi) {
                    if (chartInstances.ai) chartInstances.ai.destroy();
                    const aiObj = distData.ai || {};
                    chartInstances.ai = new Chart(ctxAi, {
                        type: "pie",
                        data: {
                            labels: ["AI-generated", "Human"],
                            datasets: [{
                                data: [aiObj["AI-generated"] || 0, aiObj["Human"] || 0],
                                backgroundColor: ["#be123c", "#15803d"],
                                borderWidth: 0,
                            }],
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            plugins: {
                                legend: { position: "bottom" },
                            },
                        },
                    });
                }
            }

            // 4. Trend Chart (Line)
            const trendResp = await fetch("/api/dashboard/trend");
            const trendData = await trendResp.json();

            if (trendResp.ok && trendData.success) {
                const ctxTrend = document.getElementById("chart-trend");
                if (ctxTrend) {
                    if (chartInstances.trend) chartInstances.trend.destroy();
                    const trendList = trendData.trend || [];
                    const trendLabels = trendList.map(t => t.date);
                    const countData = trendList.map(t => t.incident_count);
                    const avgScoreData = trendList.map(t => t.average_threat_score);

                    chartInstances.trend = new Chart(ctxTrend, {
                        type: "line",
                        data: {
                            labels: trendLabels.length > 0 ? trendLabels : ["No Data"],
                            datasets: [
                                {
                                    label: "Incident Count",
                                    data: trendLabels.length > 0 ? countData : [0],
                                    borderColor: "#c2410c",
                                    backgroundColor: "rgba(194, 65, 12, 0.12)",
                                    yAxisID: "y",
                                    tension: 0.25,
                                    fill: true,
                                },
                                {
                                    label: "Avg Threat Score",
                                    data: trendLabels.length > 0 ? avgScoreData : [0],
                                    borderColor: "#b91c1c",
                                    backgroundColor: "transparent",
                                    borderDash: [5, 5],
                                    yAxisID: "y1",
                                    tension: 0.25,
                                },
                            ],
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            plugins: {
                                legend: { position: "bottom" },
                            },
                            scales: {
                                y: {
                                    type: "linear",
                                    position: "left",
                                    beginAtZero: true,
                                    ticks: { precision: 0 },
                                    title: { display: true, text: "Count" },
                                },
                                y1: {
                                    type: "linear",
                                    position: "right",
                                    min: 0,
                                    max: 100,
                                    grid: { drawOnChartArea: false },
                                    title: { display: true, text: "Score (0-100)" },
                                },
                            },
                        },
                    });
                }
            }
        } catch (err) {
            console.error("Failed to load chart analytics:", err);
        }
    }

    // =========================================================================
    // 4. High-Risk Investigations Table Loader
    // =========================================================================
    async function loadHighRiskIncidents() {
        const tbody = document.getElementById("high-risk-tbody");
        if (!tbody) return;

        try {
            const resp = await fetch("/api/dashboard/high-risk?limit=10");
            const data = await resp.json();

            if (resp.ok && data.success && data.high_risk && data.high_risk.length > 0) {
                while (tbody.firstChild) tbody.removeChild(tbody.firstChild);
                data.high_risk.forEach(inc => {
                    tbody.appendChild(createIncidentTableRow(inc));
                });
            } else {
                renderEmptyRow(tbody, "No high-risk incidents found.");
            }
        } catch (err) {
            renderEmptyRow(tbody, "Unable to load high-risk incidents.");
        }
    }

    // =========================================================================
    // 5. Recent Incidents Table Loader
    // =========================================================================
    async function loadRecentIncidents() {
        const tbody = document.getElementById("recent-tbody");
        if (!tbody) return;

        try {
            const resp = await fetch("/api/dashboard/recent?limit=10");
            const data = await resp.json();

            if (resp.ok && data.success && data.recent && data.recent.length > 0) {
                while (tbody.firstChild) tbody.removeChild(tbody.firstChild);
                data.recent.forEach(inc => {
                    tbody.appendChild(createIncidentTableRow(inc));
                });
            } else {
                renderEmptyRow(tbody, "No incidents recorded.");
            }
        } catch (err) {
            renderEmptyRow(tbody, "Unable to load recent incidents.");
        }
    }

    // =========================================================================
    // 6. Search & Multi-Filter Table Controller (with state preservation)
    // =========================================================================
    async function executeSearch(page = 1) {
        if (!searchResultsTbody) return;

        currentPage = page;
        renderEmptyRow(searchResultsTbody, "Searching stored incidents...");
        if (searchErrorBanner) searchErrorBanner.style.display = "none";

        if (btnApplyFilters) {
            btnApplyFilters.disabled = true;
            btnApplyFilters.textContent = "Searching...";
        }

        const params = new URLSearchParams();
        params.set("page", currentPage);
        params.set("page_size", pageSize);

        const q = document.getElementById("search-q")?.value?.trim();
        if (q) params.set("q", q);

        const risk = document.getElementById("filter-risk")?.value;
        if (risk && risk !== "ALL") params.set("risk_level", risk);

        const cat = document.getElementById("filter-category")?.value;
        if (cat && cat !== "ALL") params.set("category", cat);

        const ai = document.getElementById("filter-ai")?.value;
        if (ai && ai !== "ALL") params.set("ai_label", ai);

        const minScore = document.getElementById("filter-min-score")?.value?.trim();
        if (minScore) params.set("min_score", minScore);

        const maxScore = document.getElementById("filter-max-score")?.value?.trim();
        if (maxScore) params.set("max_score", maxScore);

        const fromDate = document.getElementById("filter-from-date")?.value?.trim();
        if (fromDate) params.set("from_date", fromDate);

        const toDate = document.getElementById("filter-to-date")?.value?.trim();
        if (toDate) params.set("to_date", toDate);

        const sort = document.getElementById("filter-sort")?.value;
        if (sort) params.set("sort", sort);

        const order = document.getElementById("filter-order")?.value;
        if (order) params.set("order", order);

        try {
            const resp = await fetch(`/api/dashboard/incidents?${params.toString()}`);
            const data = await resp.json();

            if (!resp.ok || !data.success) {
                renderEmptyRow(searchResultsTbody, "Search query failed.");
                if (searchErrorBanner && searchErrorMessage) {
                    searchErrorMessage.textContent = data.error || "An error occurred during search.";
                    searchErrorBanner.style.display = "flex";
                }
                if (paginationBar) paginationBar.style.display = "none";
                return;
            }

            const items = data.items || [];
            const pag = data.pagination || { total: 0, total_pages: 0, page: 1 };

            while (searchResultsTbody.firstChild) {
                searchResultsTbody.removeChild(searchResultsTbody.firstChild);
            }

            if (items.length === 0) {
                renderEmptyRow(searchResultsTbody, "No incidents matched your query criteria.");
                if (paginationBar) paginationBar.style.display = "none";
                return;
            }

            items.forEach(inc => {
                searchResultsTbody.appendChild(createIncidentTableRow(inc));
            });

            // Update Pagination Bar
            if (paginationBar) {
                paginationBar.style.display = "flex";
                const startIdx = (pag.page - 1) * pag.page_size + 1;
                const endIdx = Math.min(pag.page * pag.page_size, pag.total);
                if (paginationInfo) {
                    paginationInfo.textContent = `Showing ${startIdx}–${endIdx} of ${pag.total} incidents`;
                }
                if (pageIndicator) {
                    pageIndicator.textContent = `Page ${pag.page} of ${pag.total_pages}`;
                }
                if (btnPrevPage) btnPrevPage.disabled = pag.page <= 1;
                if (btnNextPage) btnNextPage.disabled = pag.page >= pag.total_pages;
            }

        } catch (err) {
            renderEmptyRow(searchResultsTbody, "Unable to perform search query. Please check connection.");
            if (paginationBar) paginationBar.style.display = "none";
        } finally {
            if (btnApplyFilters) {
                btnApplyFilters.disabled = false;
                btnApplyFilters.textContent = "Search";
            }
        }
    }

    if (btnApplyFilters) {
        btnApplyFilters.addEventListener("click", () => executeSearch(1));
    }

    if (btnResetFilters) {
        btnResetFilters.addEventListener("click", () => {
            if (searchForm) searchForm.reset();
            executeSearch(1);
        });
    }

    if (btnPrevPage) {
        btnPrevPage.addEventListener("click", () => {
            if (currentPage > 1) executeSearch(currentPage - 1);
        });
    }

    if (btnNextPage) {
        btnNextPage.addEventListener("click", () => {
            executeSearch(currentPage + 1);
        });
    }

    // =========================================================================
    // 7. Initial Page Load
    // =========================================================================
    loadSummaryStats();
    loadCharts();
    loadHighRiskIncidents();
    loadRecentIncidents();
    executeSearch(1);
});
