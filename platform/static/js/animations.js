/**
 * AIShield — GSAP Animation & Welcome Screen System
 *
 * Welcome screen: 1.5s auto-dismiss on initial entry / page reload.
 * Suppressed when navigating between modules (sessionStorage flag).
 * Respects prefers-reduced-motion.
 */

// =============================================================================
// 1. NAVIGATION SUPPRESSION — set flag on internal link clicks
// =============================================================================
document.addEventListener("click", (e) => {
    const link = e.target.closest("a");
    if (link && link.href) {
        try {
            const url = new URL(link.href, window.location.origin);
            if (
                url.origin === window.location.origin &&
                !link.hasAttribute("download") &&
                link.target !== "_blank"
            ) {
                sessionStorage.setItem("aishield_navigating", "1");
            }
        } catch (_) {}
    }
});

// =============================================================================
// 2. WELCOME SCREEN — GSAP auto-dismiss 1.5s
// =============================================================================

(function initWelcomeScreen() {
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    // Legacy overlay element (5-second countdown style — now replaced)
    const legacyOverlay = document.getElementById("welcome-screen");
    // New minimal overlay
    const newOverlay = document.querySelector(".welcome-overlay");

    // Determine which overlay to use
    const overlay = newOverlay || legacyOverlay;

    if (!overlay) return;

    // Check if we should skip
    if (window.__aishield_skip_welcome) {
        overlay.style.display = "none";
        return;
    }

    if (reduced) {
        // Accessibility: skip animation immediately
        overlay.style.display = "none";
        return;
    }

    // Only show on initial entry (not internal navigation)
    // The suppression inline script in each template handles the initial fast-path.
    // This JS is the fallback controller.

    if (typeof gsap === "undefined") {
        // GSAP not loaded — dismiss after 1.5s plain JS
        setTimeout(() => {
            overlay.style.opacity = "0";
            overlay.style.transition = "opacity 0.4s ease";
            setTimeout(() => { overlay.style.display = "none"; }, 420);
        }, 1500);
        return;
    }

    // --- New minimal overlay with wordmark ---
    if (newOverlay) {
        const wordmark = newOverlay.querySelector(".welcome-wordmark");
        const bar = newOverlay.querySelector(".welcome-bar");

        const tl = gsap.timeline({
            onComplete: () => {
                gsap.to(newOverlay, {
                    opacity: 0,
                    duration: 0.35,
                    ease: "power2.inOut",
                    onComplete: () => { newOverlay.style.display = "none"; }
                });
            }
        });

        if (wordmark) {
            tl.to(wordmark, {
                opacity: 1,
                y: 0,
                duration: 0.5,
                ease: "power3.out"
            });
        }

        if (bar) {
            tl.to(bar, {
                width: "100%",
                duration: 0.9,
                ease: "power2.inOut"
            }, "-=0.1");
        }

        // Hold briefly then fade out
        tl.to({}, { duration: 0.15 });
        // (onComplete handles the fade)
        return;
    }

    // --- Legacy countdown overlay — animate and auto-dismiss at 1.5s ---
    if (legacyOverlay) {
        // Hide countdown timer UI elements if present (new design doesn't need them)
        const progressBar = document.getElementById("welcome-progress-bar");
        const countdown = document.getElementById("welcome-countdown");
        const skipBtn = document.getElementById("welcome-skip-btn");

        // Short 1.5s auto-dismiss instead of 5s
        const DURATION = 1500;

        if (progressBar) {
            gsap.to(progressBar, {
                width: "100%",
                duration: DURATION / 1000,
                ease: "power1.inOut"
            });
        }

        if (countdown) {
            let remaining = 2;
            const countEl = countdown;
            countEl.textContent = `${remaining}s`;
            const iv = setInterval(() => {
                remaining = Math.max(0, remaining - 1);
                countEl.textContent = `${remaining}s`;
                if (remaining === 0) clearInterval(iv);
            }, 500);
        }

        if (skipBtn) {
            skipBtn.addEventListener("click", () => dismissWelcome(legacyOverlay));
        }

        setTimeout(() => dismissWelcome(legacyOverlay), DURATION);
    }

    function dismissWelcome(el) {
        gsap.to(el, {
            opacity: 0,
            duration: 0.35,
            ease: "power2.inOut",
            onComplete: () => { el.style.display = "none"; }
        });
    }
})();

// =============================================================================
// 3. MAIN PAGE ANIMATIONS — runs after DOM ready
// =============================================================================

document.addEventListener("DOMContentLoaded", () => {
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduced) return;
    if (typeof gsap === "undefined") return;

    // Register ScrollTrigger if available
    if (typeof ScrollTrigger !== "undefined") {
        gsap.registerPlugin(ScrollTrigger);
    }

    // --- Shell entrance ---
    const sidebar = document.querySelector(".app-sidebar");
    const topbar  = document.querySelector(".app-topbar");

    if (topbar) {
        gsap.from(topbar, { opacity: 0, y: -8, duration: 0.3, ease: "power2.out", clearProps: "all" });
    }

    if (sidebar) {
        gsap.from(sidebar, { opacity: 0, x: -10, duration: 0.35, ease: "power2.out", clearProps: "all" });
    }

    // --- Page header ---
    const pageHeader = document.querySelector(".page-header");
    if (pageHeader) {
        gsap.from(pageHeader, {
            opacity: 0, y: 10,
            duration: 0.4, ease: "power2.out",
            delay: 0.1,
            clearProps: "all"
        });
    }

    // --- Metric cells stagger ---
    const metricCells = document.querySelectorAll(
        ".dash-metric-cell, .live-metric-cell, .graph-stat-cell, .metric-cell"
    );
    if (metricCells.length > 0) {
        gsap.from(metricCells, {
            opacity: 0,
            y: 8,
            duration: 0.35,
            stagger: 0.04,
            ease: "power2.out",
            delay: 0.15,
            clearProps: "all"
        });
    }

    // --- Cards / sections stagger ---
    const cards = document.querySelectorAll(
        ".card, .chart-card, .connector-card, .gnn-card, .campaigns-card, .source-status-card"
    );
    if (cards.length > 0) {
        gsap.from(cards, {
            opacity: 0,
            y: 12,
            duration: 0.4,
            stagger: 0.06,
            ease: "power2.out",
            delay: 0.18,
            clearProps: "all"
        });
    }

    // --- Metric value counters ---
    const metricValues = document.querySelectorAll(
        ".dash-metric-value, .live-metric-val, .graph-stat-val, .summary-val"
    );
    metricValues.forEach((el) => {
        const raw = el.textContent.trim();
        const num = parseFloat(raw.replace(/,/g, ""));
        if (!isNaN(num) && num > 0 && num < 100000 && !raw.includes("%") && !raw.includes(".")) {
            const obj = { val: 0 };
            gsap.to(obj, {
                val: num,
                duration: 0.7,
                ease: "power1.out",
                delay: 0.3,
                onUpdate: () => {
                    el.textContent = Math.round(obj.val).toLocaleString();
                }
            });
        }
    });

    // --- Mobile sidebar toggle ---
    const mobileBtn = document.getElementById("mobile-menu-btn");
    const appSidebar = document.querySelector(".app-sidebar");
    if (mobileBtn && appSidebar) {
        mobileBtn.addEventListener("click", () => {
            const isOpen = appSidebar.classList.toggle("sidebar-open");
            mobileBtn.setAttribute("aria-expanded", isOpen ? "true" : "false");
        });

        // Close sidebar when clicking outside on mobile
        document.addEventListener("click", (e) => {
            if (
                window.innerWidth < 1024 &&
                appSidebar.classList.contains("sidebar-open") &&
                !appSidebar.contains(e.target) &&
                !mobileBtn.contains(e.target)
            ) {
                appSidebar.classList.remove("sidebar-open");
                mobileBtn.setAttribute("aria-expanded", "false");
            }
        });
    }
});

// =============================================================================
// 4. PUBLIC API — reusable animation helpers
// =============================================================================

window.AIShieldAnimate = {
    /**
     * Animate a newly inserted live stream event.
     * @param {HTMLElement} el
     */
    liveEventInsert(el) {
        if (!el || typeof gsap === "undefined") return;
        if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
        gsap.from(el, {
            opacity: 0,
            y: -8,
            duration: 0.25,
            ease: "power2.out",
            clearProps: "all"
        });
    },

    /**
     * Animate element reveal (for dynamically rendered content).
     * @param {HTMLElement} el
     */
    revealElement(el) {
        if (!el || typeof gsap === "undefined") return;
        if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
        gsap.from(el, {
            opacity: 0,
            y: 8,
            duration: 0.3,
            ease: "power2.out",
            clearProps: "all"
        });
    },

    /**
     * Animate a results section appearing after analysis.
     * @param {HTMLElement} el
     */
    showResults(el) {
        if (!el || typeof gsap === "undefined") return;
        if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
            el.style.display = "";
            return;
        }
        el.style.display = "";
        gsap.from(el, {
            opacity: 0,
            y: 16,
            duration: 0.45,
            ease: "power3.out",
            clearProps: "all"
        });
    },

    /**
     * Animate node inspector slide-in on graph.
     * @param {HTMLElement} el
     */
    showInspector(el) {
        if (!el || typeof gsap === "undefined") return;
        if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
            el.classList.add("inspector-visible");
            return;
        }
        el.classList.add("inspector-visible");
        gsap.from(el, {
            opacity: 0,
            x: 12,
            duration: 0.3,
            ease: "power2.out",
            clearProps: "opacity,x"
        });
    },

    /**
     * Animate a prediction row appearing in GNN table.
     * @param {HTMLElement} el
     */
    gnnRowReveal(el) {
        if (!el || typeof gsap === "undefined") return;
        if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
        gsap.from(el, {
            opacity: 0,
            x: -6,
            duration: 0.2,
            ease: "power2.out",
            clearProps: "all"
        });
    }
};
