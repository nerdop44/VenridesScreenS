/* ==========================================================================
   VScreenS TV Client 3.0
   Experiencia de señalización: video, sidebar rotativa, ticker y alertas.
   ========================================================================== */

(function () {
    "use strict";

    /* ---------------------------------------------------------------------
       Configuración y estado
       --------------------------------------------------------------------- */

    var API_URL = window.VSCREENS_API_URL || "https://vscreens-api.inverpave.com";
    var params = new URLSearchParams(window.location.search);
    var previewCompanyId = params.get("preview") || params.get("company");
    var previewToken = params.get("pt") || params.get("token") || "";
    var DEVICE_KEY = "device_uuid";
    var CACHE_KEY = "vscreens_last_config";

    var state = {
        uuid: getDeviceUuid(),
        config: null,
        lastUpdated: null,
        pollTimer: null,
        clockOffsetMs: 0,
        sidebarSlides: [],
        slideIndex: 0,
        slideTimer: null,
        tickerTimer: null,
        alertTimer: null,
        activeAlertId: null,
        queue: [],
        queueSignature: "",
        manualOverride: null,
        overrideTimer: null,
        cueTimer: null,
        cuedId: null,
        lastPlaylist: [],
        lastScheduled: [],
        videoIndex: 0,
        failedVideos: {},
        player: null,
        playerReady: false,
        playerLoading: false,
        playerFresh: false,
        currentItem: null,
        currentKind: null,
        muted: false,
        priorityReturnItem: null,
        inPriority: false,
        priorityUrl: null,
        pingTimer: null,
        fallbackTimer: null,
        fallbackIndex: 0,
        soundHideTimer: null,
        adTimer: null,
        lastPingAt: 0
    };

    /* ---------------------------------------------------------------------
       Utilidades
       --------------------------------------------------------------------- */

    function $(id) {
        return document.getElementById(id);
    }

    function parseJson(value, fallback) {
        if (value === null || value === undefined || value === "") return fallback;
        if (typeof value === "object") return value;
        try {
            return JSON.parse(value);
        } catch (err) {
            return fallback;
        }
    }

    function pad2(value) {
        value = String(value);
        return value.length < 2 ? "0" + value : value;
    }

    function getDeviceUuid() {
        var uuid = null;
        try {
            uuid = window.localStorage.getItem(DEVICE_KEY);
        } catch (err) {
            uuid = null;
        }
        if (!uuid) {
            if (window.crypto && typeof window.crypto.randomUUID === "function") {
                uuid = window.crypto.randomUUID();
            } else {
                uuid = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, function (c) {
                    var r = (Math.random() * 16) | 0;
                    var v = c === "x" ? r : (r & 0x3) | 0x8;
                    return v.toString(16);
                });
            }
            try {
                window.localStorage.setItem(DEVICE_KEY, uuid);
            } catch (err) {
                /* almacenamiento no disponible en algunos televisores */
            }
        }
        return uuid;
    }

    function isYoutubeUrl(url) {
        return typeof url === "string" && /youtube\.com|youtu\.be/i.test(url);
    }

    function extractYoutubeId(url) {
        if (!url) return null;
        var value = String(url).trim();
        if (/^[a-zA-Z0-9_-]{11}$/.test(value)) return value;
        var match = value.match(/(?:youtube\.com\/(?:[^\/]+\/.+\/|(?:v|e(?:mbed)?|shorts|live)\/|.*[?&]v=)|youtu\.be\/)([^"&?\/\s]{11})/);
        return match ? match[1] : null;
    }

    function driveToDirect(url) {
        if (!url) return url;
        if (!/drive\.google\.com|docs\.google\.com/i.test(url)) return url;
        var match = url.match(/(?:\/d\/|id=|open\?id=)([-\w]{15,})/) || url.match(/([-\w]{25,})/);
        if (match && match[1]) {
            return "https://drive.google.com/uc?export=download&id=" + match[1];
        }
        return url;
    }

    function driveToImage(url) {
        if (!url) return url;
        if (!/drive\.google\.com|docs\.google\.com/i.test(url)) return url;
        var match = url.match(/(?:\/d\/|id=|open\?id=)([-\w]{15,})/) || url.match(/([-\w]{25,})/);
        if (match && match[1]) {
            return "https://lh3.googleusercontent.com/d/" + match[1] + "=w1200";
        }
        return url;
    }

    function absoluteUrl(url) {
        if (!url) return "";
        if (/^(https?:|data:|blob:)/i.test(url)) return url;
        if (url.charAt(0) === "/") return API_URL + url;
        return API_URL + "/" + url.replace(/^\.?\//, "");
    }

    function contrastColor(hex) {
        if (!hex || typeof hex !== "string") return "#ffffff";
        var value = hex.replace("#", "");
        if (value.length === 3) {
            value = value.charAt(0) + value.charAt(0) + value.charAt(1) + value.charAt(1) + value.charAt(2) + value.charAt(2);
        }
        if (!/^[0-9a-f]{6}$/i.test(value)) return "#ffffff";
        var r = parseInt(value.substr(0, 2), 16);
        var g = parseInt(value.substr(2, 2), 16);
        var b = parseInt(value.substr(4, 2), 16);
        var yiq = (r * 299 + g * 587 + b * 114) / 1000;
        return yiq >= 150 ? "#08111f" : "#ffffff";
    }

    function formatNumber(value, decimals) {
        var number = Number(value);
        if (!isFinite(number)) return "—";
        try {
            return number.toLocaleString("es-VE", {
                minimumFractionDigits: decimals,
                maximumFractionDigits: decimals
            });
        } catch (err) {
            return number.toFixed(decimals);
        }
    }

    function isPriceText(value) {
        return typeof value === "string" && /(^|\s)(\$|bs\.?|usd|precio)/i.test(value) && /\d/.test(value);
    }

    /* ---------------------------------------------------------------------
       Relojes y fecha
       --------------------------------------------------------------------- */

    var DAYS_SHORT = ["DOM", "LUN", "MAR", "MIÉ", "JUE", "VIE", "SÁB"];
    var DAYS_LONG = ["DOMINGO", "LUNES", "MARTES", "MIÉRCOLES", "JUEVES", "VIERNES", "SÁBADO"];
    var MONTHS_SHORT = ["ENE", "FEB", "MAR", "ABR", "MAY", "JUN", "JUL", "AGO", "SEP", "OCT", "NOV", "DIC"];
    var MONTHS_LONG = ["ENERO", "FEBRERO", "MARZO", "ABRIL", "MAYO", "JUNIO", "JULIO", "AGOSTO", "SEPTIEMBRE", "OCTUBRE", "NOVIEMBRE", "DICIEMBRE"];

    function updateClocks() {
        var now = new Date(Date.now() + (state.clockOffsetMs || 0));
        var time = pad2(now.getHours()) + ":" + pad2(now.getMinutes());
        var sideClock = $("side-clock");
        var bottomTime = $("bottom-time");
        var bottomDay = $("bottom-day");
        var topDate = $("topbar-date");

        if (sideClock) sideClock.textContent = time;
        if (bottomTime) bottomTime.textContent = time;
        if (bottomDay) {
            bottomDay.textContent = DAYS_SHORT[now.getDay()] + " · " + pad2(now.getDate()) + " " + MONTHS_SHORT[now.getMonth()];
        }
        if (topDate) {
            topDate.textContent = DAYS_LONG[now.getDay()] + ", " + now.getDate() + " DE " + MONTHS_LONG[now.getMonth()] + " " + now.getFullYear();
        }
    }

    /* ---------------------------------------------------------------------
       Carga de configuración (con caché offline y timer único)
       --------------------------------------------------------------------- */

    function configUrl() {
        var base = previewCompanyId
            ? API_URL + "/companies/" + encodeURIComponent(previewCompanyId) + "/preview-config" +
              (previewToken ? "?pt=" + encodeURIComponent(previewToken) : "")
            : API_URL + "/devices/" + encodeURIComponent(state.uuid) + "/config";
        return base + (base.indexOf("?") === -1 ? "?" : "&") + "_t=" + Date.now();
    }

    function schedulePoll(ms) {
        if (state.pollTimer) {
            window.clearTimeout(state.pollTimer);
            state.pollTimer = null;
        }
        state.pollTimer = window.setTimeout(fetchConfig, ms || 10000);
    }

    function loadCachedConfig() {
        if (previewCompanyId) return null;
        try {
            var raw = localStorage.getItem(CACHE_KEY);
            return raw ? JSON.parse(raw) : null;
        } catch (e) {
            return null;
        }
    }

    function saveCachedConfig(data) {
        if (previewCompanyId || !data) return;
        try {
            localStorage.setItem(CACHE_KEY, JSON.stringify(data));
        } catch (e) { /* quota */ }
    }

    function fetchConfig() {
        if (state.pollTimer) {
            window.clearTimeout(state.pollTimer);
            state.pollTimer = null;
        }
        var url = configUrl();
        var controller = typeof AbortController !== "undefined" ? new AbortController() : null;
        var abortTimer = controller ? window.setTimeout(function () { controller.abort(); }, 15000) : null;

        fetch(url, { cache: "no-store", signal: controller ? controller.signal : undefined })
            .then(function (response) {
                var srvDate = response.headers && response.headers.get("Date");
                if (srvDate) {
                    var parsed = Date.parse(srvDate);
                    if (isFinite(parsed)) state.clockOffsetMs = parsed - Date.now();
                }
                if (response.status === 404) {
                    if (!previewCompanyId) {
                        try { localStorage.removeItem(CACHE_KEY); } catch (e) { }
                        var fallbackSub = $("fallback-sub");
                        if (fallbackSub) fallbackSub.textContent = "Contenido en reproducción";
                        showRegistration();
                    }
                    return null;
                }
                if (!response.ok) throw new Error("HTTP " + response.status);
                return response.json();
            })
            .then(function (data) {
                if (!data) return;
                saveCachedConfig(data);
                if (data.last_updated && data.last_updated === state.lastUpdated) {
                    handlePing(data);
                    return;
                }
                state.lastUpdated = data.last_updated || null;
                applyConfig(data, false);
            })
            .catch(function (error) {
                if (!state.config && !previewCompanyId) {
                    var cached = loadCachedConfig();
                    if (cached) {
                        console.info("VScreenS: cargando configuración desde caché offline");
                        applyConfig(cached, true);
                    } else {
                        var fallbackSub = $("fallback-sub");
                        if (fallbackSub) fallbackSub.textContent = "Reconectando con VScreenS…";
                        showRegistration("Sin conexión con el servidor. Reintentando…");
                    }
                }
                console.warn("VScreenS config error:", error);
            })
            .then(function () {
                if (abortTimer) window.clearTimeout(abortTimer);
                schedulePoll(10000);
            });
    }

    /* ---------------------------------------------------------------------
       Aplicación de configuración
       --------------------------------------------------------------------- */

    function applyConfig(data, force) {
        state.config = data;

        var design = parseJson(data.design_settings, {}) || {};
        var sidebarItems = parseJson(data.sidebar_content, []) || [];
        var bottom = parseJson(data.bottom_bar_content, {}) || {};
        var playlist = parseJson(data.video_playlist, []) || [];
        var scheduled = parseJson(data.scheduled_videos, []) || [];
        var menus = parseJson(data.menus, []) || [];

        if (data.is_active === false && !previewCompanyId) {
            showSuspended(data.error);
            return;
        }

        hideOverlay("kill-switch");

        applyTheme(data, design);
        applyBrand(data, design);
        buildSidebar(sidebarItems, menus, design);
        buildOdooWidget(data.odoo_widget);
        buildTicker(bottom, data, design);
        buildQueue(playlist, scheduled, data);
        handlePriority(data.priority_content_url || null);
        handleAlert(data.active_alert);
        handlePing(data);

        if (!data.allow_youtube_control) {
            clearYoutubeOverride();
        }

        var splash = $("splash");
        if (splash) splash.classList.add("is-hidden");

        var fallbackSub = $("fallback-sub");
        if (fallbackSub) fallbackSub.textContent = "Contenido en reproducción";

        if (force) {
            state.lastUpdated = data.last_updated || state.lastUpdated;
        }
    }

    function applyTheme(data, design) {
        var app = $("tv-app");
        var root = document.documentElement;

        root.style.setProperty("--vs-primary", data.primary_color || "#12233d");
        root.style.setProperty("--vs-secondary", data.secondary_color || "#c8ff00");
        root.style.setProperty("--vs-accent", data.accent_color || "#ff6b35");
        root.style.setProperty("--vs-highlight", data.secondary_color || "#c8ff00");

        if (app) {
            app.className = "tv-app " + (data.layout_type || "layout-a");
        }

        if (design.safety_margin !== undefined && design.safety_margin !== null && design.safety_margin !== "") {
            root.style.setProperty("--safe", Number(design.safety_margin) + "vw");
        } else {
            root.style.setProperty("--safe", "clamp(14px, 2vw, 34px)");
        }

        if (design.sidebar_width) {
            root.style.setProperty("--sidebar-w", Number(design.sidebar_width) + "vw");
        }

        if (design.bottom_bar_height) {
            root.style.setProperty("--bottom-h", Number(design.bottom_bar_height) + "vh");
        }

        var sidebar = $("sidebar");
        if (sidebar) {
            var bg = design.sidebar_bg_image ? driveToImage(design.sidebar_bg_image) : "";
            if (bg) {
                sidebar.style.backgroundImage = "linear-gradient(180deg, rgba(4,8,15,0.58) 0%, rgba(4,8,15,0.9) 72%, rgba(4,8,15,0.97) 100%), url(\"" + bg + "\")";
                sidebar.style.backgroundSize = "cover";
                sidebar.style.backgroundPosition = "center";
            } else {
                sidebar.style.backgroundImage = "";
            }
            sidebar.classList.remove("effect-glass-3d", "effect-neon-glow", "effect-deep-shadow");
            if (design.sidebar_effect === "glass_3d") sidebar.classList.add("effect-glass-3d");
            if (design.sidebar_effect === "neon_glow") sidebar.classList.add("effect-neon-glow");
            if (design.sidebar_effect === "deep_shadow") sidebar.classList.add("effect-deep-shadow");
        }
    }

    function applyBrand(data, design) {
        var nameEl = $("company-name");
        if (nameEl) {
            nameEl.textContent = data.name || "VScreenS";
            nameEl.style.fontFamily = design.name_font || "";
            nameEl.style.fontSize = design.name_size || "";
            nameEl.style.color = design.name_color || "";
            nameEl.style.fontWeight = design.name_weight || "";
            window.requestAnimationFrame(function () { fitBrandText(nameEl); });
        }

        var kicker = $("side-kicker");
        if (kicker) {
            kicker.textContent = (data.sidebar_header_value || "CONTENIDO DESTACADO").toString().toUpperCase();
        }

        var logo = $("side-logo");
        if (logo) {
            var logoUrl = design.sidebar_bottom_logo || data.logo_url || "";
            if (logoUrl) {
                logo.src = absoluteUrl(driveToImage(logoUrl));
                logo.onerror = function () {
                    logo.onerror = null;
                    logo.src = "vscreens_icon.png";
                };
            } else {
                logo.src = "vscreens_icon.png";
            }
            if (design.sidebar_bottom_logo_size) {
                var size = Math.max(40, Math.min(100, Number(design.sidebar_bottom_logo_size)));
                logo.style.width = size + "%";
                logo.style.height = size + "%";
            }
        }

        var fallbackTitle = $("fallback-title");
        if (fallbackTitle) fallbackTitle.textContent = data.name || "VScreenS";

        var bcvPill = $("bcv-pill");
        if (bcvPill) {
            bcvPill.classList.toggle("hidden", design.show_bcv === false || !data.bcv_rate);
        }

        var subEl = document.querySelector(".side-brand-sub");
        if (subEl) {
            var subText = design.side_subtitle !== undefined && design.side_subtitle !== null
                ? String(design.side_subtitle).trim()
                : "PANTALLAS PUBLI-INTELIGENTES";
            subEl.textContent = subText;
            subEl.classList.toggle("hidden", !subText);
        }

        var sideFooter = document.querySelector(".side-footer");
        if (sideFooter) {
            sideFooter.classList.toggle("hidden", design.show_side_footer === false);
            sideFooter.classList.remove("footer-anim-marquee", "footer-anim-pulse", "footer-anim-fade_slide", "footer-anim-none");
            sideFooter.classList.add("footer-anim-" + (design.side_footer_animation || "marquee"));
        }
        var sideFooterText = document.querySelector(".side-footer-text");
        if (sideFooterText) {
            var footerTxt = design.side_footer_text !== undefined && design.side_footer_text !== null && String(design.side_footer_text).trim() !== ""
                ? String(design.side_footer_text)
                : "VScreenS · Señalización inteligente";
            sideFooterText.textContent = footerTxt;
        }
        var sideClock = $("side-clock");
        if (sideClock) {
            sideClock.classList.toggle("hidden", design.show_side_clock !== true);
        }
        var bottomClock = document.querySelector(".bottom-clock");
        if (bottomClock) {
            bottomClock.classList.toggle("hidden", design.show_bottom_clock === false);
        }
        var topDate = $("topbar-date");
        if (topDate) {
            topDate.classList.toggle("hidden", design.show_topbar_date === false);
        }
        var liveBadge = document.querySelector(".live-badge");
        if (liveBadge) {
            liveBadge.classList.toggle("hidden", design.show_live_badge === false);
        }
        var sideCounter = $("side-counter");
        if (sideCounter) {
            sideCounter.classList.toggle("hidden", design.show_slide_counter !== true);
        }
    }

    function fitBrandText(el) {
        if (!el || !el.parentElement) return;
        var maxW = el.parentElement.clientWidth;
        if (!maxW || maxW < 40) return;
        var computed = window.getComputedStyle(el);
        var size = parseFloat(computed.fontSize) || 20;
        var minSize = 11;
        while (el.scrollWidth > maxW && size > minSize) {
            size -= 0.8;
            el.style.fontSize = size + "px";
        }
    }

    /* ---------------------------------------------------------------------
       Barra lateral
       --------------------------------------------------------------------- */

    function buildSlides(items) {
        var slides = [];
        var i = 0;
        while (i < items.length) {
            var item = items[i];
            if (typeof item === "string") item = { type: "text", value: item };
            if (!item || typeof item !== "object") {
                i += 1;
                continue;
            }

            if (item.type === "image") {
                slides.push({
                    kind: "image",
                    image: item.value,
                    caption: item.caption || "",
                    eyebrow: item.eyebrow || "",
                    index: i
                });
                i += 1;
                continue;
            }

            var value = item.value !== undefined ? item.value : item.text;
            if (!value) {
                i += 1;
                continue;
            }

            var next = items[i + 1];
            if (typeof next === "string") next = { type: "text", value: next };

            var slide = {
                kind: "text",
                title: String(value),
                titleColor: item.color || null,
                sub: "",
                subColor: null,
                price: "",
                priceColor: null,
                imageUrl: item.image_url || item.image || "",
                eyebrow: item.eyebrow || (item.label && item.label !== value ? String(item.label) : ""),
                fontFamily: item.font_family || "",
                weight: item.weight || "",
                index: i
            };

            if (next && typeof next === "object" && next.type !== "image" && (next.value || next.text)) {
                var nextValue = String(next.value !== undefined ? next.value : next.text);
                if (!slide.imageUrl && (next.image_url || next.image)) {
                    slide.imageUrl = next.image_url || next.image;
                }
                if (isPriceText(nextValue)) {
                    slide.price = nextValue;
                    slide.priceColor = next.color || null;
                } else if (isPriceText(value)) {
                    slide.price = String(value);
                    slide.priceColor = item.color || null;
                    slide.title = nextValue;
                    slide.titleColor = next.color || null;
                    slide.sub = "";
                } else {
                    slide.sub = nextValue;
                    slide.subColor = next.color || null;
                }
                i += 2;
            } else {
                if (isPriceText(value)) {
                    slide.price = String(value);
                    slide.priceColor = item.color || null;
                    slide.title = "";
                }
                i += 1;
            }

            if (!slide.title && !slide.price) {
                continue;
            }
            slides.push(slide);
        }
        return slides;
    }

    function buildSidebar(items, menus, design) {
        state.sidebarSlides = buildSlides(items);
        if (!state.sidebarSlides.length) {
            state.sidebarSlides = [{
                kind: "text",
                title: "Bienvenidos",
                titleColor: null,
                sub: state.config ? state.config.name : "VScreenS",
                subColor: null,
                eyebrow: "VScreenS",
                price: "",
                index: 0
            }];
        }

        var stage = $("side-stage");
        if (stage) {
            stage.classList.remove("anim-fade", "anim-slide_up", "anim-slide_left", "anim-zoom", "anim-none");
            var anim = (design && design.sidebar_animation) || "slide_up";
            if (anim !== "slide_up") stage.classList.add("anim-" + anim);

            stage.classList.remove("font-scale-compact", "font-scale-normal", "font-scale-large");
            var fscale = (design && design.sidebar_font_scale) || "normal";
            stage.classList.add("font-scale-" + fscale);
        }

        state.slideIndex = 0;
        renderSlide(true);
        startSlideRotation(design);

        buildMenu(menus);
    }

    function renderSlide(initial) {
        var stage = $("side-stage");
        if (!stage) return;
        var slides = state.sidebarSlides;
        if (!slides.length) return;

        var slide = slides[state.slideIndex % slides.length];
        var design = (state.config && parseJson(state.config.design_settings, {})) || {};
        var noFrame = design.show_card_frame === false ? " no-frame" : "";
        var card = document.createElement("article");
        card.className = "promo-card" + noFrame + (initial ? " is-entering" : " is-entering");

        if (slide.kind === "image") {
            var cover = document.createElement("img");
            cover.className = "promo-image-cover";
            cover.alt = "";
            cover.src = absoluteUrl(driveToImage(slide.image));
            cover.onerror = function () {
                cover.style.display = "none";
            };
            card.appendChild(cover);

            var overlay = document.createElement("div");
            overlay.className = "promo-overlay";
            card.appendChild(overlay);

            if (slide.eyebrow) {
                var eyebrowImg = document.createElement("div");
                eyebrowImg.className = "promo-eyebrow";
                eyebrowImg.textContent = slide.eyebrow;
                card.appendChild(eyebrowImg);
            }

            if (slide.caption) {
                var caption = document.createElement("div");
                caption.className = "promo-title";
                caption.textContent = slide.caption;
                card.appendChild(caption);
            }
        } else {
            var eyebrow = document.createElement("div");
            eyebrow.className = "promo-eyebrow";
            eyebrow.textContent = slide.eyebrow || "DESTACADO";
            card.appendChild(eyebrow);

            if (slide.title) {
                var title = document.createElement("h2");
                title.className = "promo-title";
                title.textContent = slide.title;
                if (slide.titleColor) title.style.color = slide.titleColor;
                if (slide.fontFamily) title.style.fontFamily = slide.fontFamily;
                if (slide.weight) title.style.fontWeight = slide.weight;
                card.appendChild(title);
            }

            if (slide.sub) {
                var sub = document.createElement("p");
                sub.className = "promo-sub";
                sub.textContent = slide.sub;
                if (slide.subColor) sub.style.color = slide.subColor;
                card.appendChild(sub);
            }

            if (slide.price) {
                var price = document.createElement("div");
                price.className = "promo-price";
                price.textContent = slide.price;
                if (slide.priceColor) price.style.color = slide.priceColor;
                card.appendChild(price);
            }

            if (slide.imageUrl) {
                var imgWrap = document.createElement("div");
                imgWrap.className = "promo-inline-image-wrap";
                var imgEl = document.createElement("img");
                imgEl.className = "promo-inline-image";
                imgEl.alt = slide.title || "";
                imgEl.src = absoluteUrl(driveToImage(slide.imageUrl));
                imgEl.onerror = function () {
                    imgWrap.style.display = "none";
                };
                imgWrap.appendChild(imgEl);
                card.appendChild(imgWrap);
            }
        }

        var previous = stage.querySelector(".promo-card");
        if (previous && !initial) {
            previous.classList.add("is-leaving");
            window.setTimeout(function () {
                if (previous.parentNode) previous.parentNode.removeChild(previous);
            }, 340);
        } else if (previous) {
            stage.removeChild(previous);
        }

        stage.appendChild(card);

        var counterEl = $("side-counter");
        if (counterEl) {
            counterEl.textContent = pad2((state.slideIndex % slides.length) + 1) + " / " + pad2(slides.length);
        }
    }

    function startSlideRotation(design) {
        if (state.slideTimer) window.clearInterval(state.slideTimer);
        var configured = Number((state.config && state.config.pause_duration) || 10);
        var seconds = Math.max(7, Math.min(45, configured));
        state.slideTimer = window.setInterval(function () {
            if (state.sidebarSlides.length <= 1) return;
            state.slideIndex = (state.slideIndex + 1) % state.sidebarSlides.length;
            renderSlide(false);
        }, seconds * 1000);
    }

    function buildMenu(menus) {
        var container = $("side-menu");
        if (!container) return;
        container.innerHTML = "";
        if (!Array.isArray(menus) || !menus.length) {
            container.classList.add("hidden");
            return;
        }

        container.classList.remove("hidden");
        var visible = menus.filter(function (item) {
            return item && (item.name || item.title);
        }).slice(0, 5);

        visible.forEach(function (item) {
            var row = document.createElement("div");
            row.className = "menu-row";

            var name = document.createElement("span");
            name.className = "menu-name";
            name.textContent = item.name || item.title;
            row.appendChild(name);

            var dots = document.createElement("span");
            dots.className = "menu-dots";
            row.appendChild(dots);

            var price = document.createElement("span");
            price.className = "menu-price";
            var amount = Number(item.price);
            price.textContent = isFinite(amount) && amount > 0 ? "$" + formatNumber(amount, 2) : "";
            row.appendChild(price);

            container.appendChild(row);
        });

        if (!visible.length) container.classList.add("hidden");
    }

    /* ---------------------------------------------------------------------
       Ticker y barra inferior
       --------------------------------------------------------------------- */

    function buildOdooWidget(widget) {
        var root = $("odoo-widget");
        if (!root) return;
        root.innerHTML = "";
        if (!widget || !widget.enabled || !Array.isArray(widget.records) || !widget.records.length) {
            root.classList.add("hidden");
            return;
        }
        root.classList.remove("hidden");
        if (widget.color) root.style.borderLeftColor = widget.color;

        var title = document.createElement("div");
        title.className = "odoo-widget-title";
        var icon = document.createElement("i");
        icon.className = "fa " + (widget.icon || "fa-file-text");
        if (widget.color) icon.style.color = widget.color;
        title.appendChild(icon);
        title.appendChild(document.createTextNode(widget.label || "Odoo"));
        root.appendChild(title);

        widget.records.slice(0, 8).forEach(function (record) {
            var row = document.createElement("div");
            row.className = "odoo-widget-row";
            var name = document.createElement("span");
            name.textContent = record.title || "";
            row.appendChild(name);
            var values = Array.isArray(record.values) ? record.values : [];
            if (values.length) {
                var value = document.createElement("span");
                value.textContent = values.map(function (v) { return v.value; }).filter(Boolean).join(" · ");
                row.appendChild(value);
            }
            if (record.url) {
                row.addEventListener("click", function () {
                    window.open(record.url, "_blank", "noopener");
                });
            }
            root.appendChild(row);
        });
    }

    function buildTicker(bottom, data, design) {
        var track = $("ticker-track");
        if (!track) return;
        track.innerHTML = "";

        var items = [];
        var messages = bottom && Array.isArray(bottom.messages) ? bottom.messages : [];
        if (messages.length) {
            messages.forEach(function (message) {
                if (message) items.push(String(message));
            });
        } else if (bottom && bottom.static) {
            items.push(String(bottom.static));
        }

        if (!items.length) {
            items.push("Bienvenidos a " + (data.name || "VScreenS"));
        }

        if (data.bcv_rate && design.show_bcv !== false) {
            items.push("Tasa BCV: Bs. " + formatNumber(data.bcv_rate, 2));
        }

        var showSocialInTicker = !design || design.show_social_in_ticker !== false;
        var whatsapp = bottom.whatsapp || data.whatsapp;
        var instagram = bottom.instagram || data.instagram;
        var facebook = bottom.facebook || data.facebook;
        var tiktok = bottom.tiktok || data.tiktok;

        if (showSocialInTicker) {
            if (whatsapp) items.push("WhatsApp: " + whatsapp);
            if (instagram) items.push("Instagram: @" + String(instagram).replace(/^@/, ""));
            if (facebook) items.push("Facebook: " + facebook);
            if (tiktok) items.push("TikTok: @" + String(tiktok).replace(/^@/, ""));
            var phone = data.phone;
            if (phone && String(phone) !== String(whatsapp || "")) items.push("Teléfono: " + phone);
        }

        var itemStyle = {};
        if (bottom && bottom.color) itemStyle.color = bottom.color;
        if (design && design.ticker_color) itemStyle.color = design.ticker_color;
        if (bottom && bottom.font_size) itemStyle.fontSize = bottom.font_size;
        if (design && design.ticker_font) itemStyle.fontFamily = design.ticker_font;

        items.forEach(function (text) {
            var el = document.createElement("span");
            el.className = "ticker-item";
            el.textContent = text;
            if (itemStyle.color) el.style.color = itemStyle.color;
            if (itemStyle.fontSize) el.style.fontSize = itemStyle.fontSize;
            if (itemStyle.fontFamily) el.style.fontFamily = itemStyle.fontFamily;

            var diamond = document.createElement("i");
            diamond.className = "ticker-diamond";
            el.insertBefore(diamond, el.firstChild);
            track.appendChild(el);
        });

        // Duplicar el bloque para un bucle continuo sin saltos.
        var original = track.innerHTML;
        track.innerHTML = original + original;

        var mask = track.parentNode;
        if (mask && track.scrollWidth < mask.clientWidth * 1.5) {
            track.innerHTML = original + original + original + original;
        }

        var speed = Number((design && design.ticker_speed) || 34);
        var duration = Math.max(22, Math.min(60, speed));
        track.style.setProperty("--ticker-duration", duration + "s");
        track.style.animation = "none";
        void track.offsetWidth;
        track.style.animation = "";

        var bcv = $("bcv-value");
        if (bcv) {
            bcv.textContent = data.bcv_rate ? "Bs. " + formatNumber(data.bcv_rate, 2) : "Bs. —";
        }

        buildSocialPills(bottom, data, design);
    }

    function buildSocialPills(bottom, data, design) {
        var container = $("social-pill");
        if (!container) return;
        container.innerHTML = "";
        if (!design || design.show_social_in_ticker !== false) {
            container.classList.add("hidden");
            return;
        }
        container.classList.remove("hidden");

        var whatsapp = bottom.whatsapp || data.whatsapp;
        var instagram = bottom.instagram || data.instagram;
        var facebook = bottom.facebook || data.facebook;
        var tiktok = bottom.tiktok || data.tiktok;

        if (whatsapp) {
            var wa = document.createElement("span");
            wa.className = "social-item whatsapp";
            wa.innerHTML = '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347m-5.421 7.403h-.004a9.87 9.87 0 01-5.031-1.378l-.361-.214-3.741.982.998-3.648-.235-.374a9.86 9.86 0 01-1.51-5.26c.001-5.45 4.436-9.884 9.888-9.884 2.64 0 5.122 1.03 6.988 2.898a9.825 9.825 0 012.893 6.994c-.003 5.45-4.437 9.884-9.885 9.884m8.413-18.297A11.815 11.815 0 0012.05 0C5.495 0 .16 5.335.157 11.892c0 2.096.547 4.142 1.588 5.945L.057 24l6.305-1.654a11.882 11.882 0 005.683 1.448h.005c6.554 0 11.89-5.335 11.893-11.893a11.821 11.821 0 00-3.48-8.413Z"/></svg>';
            var waText = document.createElement("span");
            waText.textContent = whatsapp;
            wa.appendChild(waText);
            container.appendChild(wa);
        }

        if (instagram) {
            var ig = document.createElement("span");
            ig.className = "social-item instagram";
            ig.innerHTML = '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 2.163c3.204 0 3.584.012 4.85.07 3.252.148 4.771 1.691 4.919 4.919.058 1.265.069 1.645.069 4.849 0 3.205-.012 3.584-.069 4.849-.149 3.225-1.664 4.771-4.919 4.919-1.266.058-1.644.07-4.85.07-3.204 0-3.584-.012-4.849-.07-3.26-.149-4.771-1.699-4.919-4.92-.058-1.265-.07-1.644-.07-4.849 0-3.204.013-3.583.07-4.849.149-3.227 1.664-4.771 4.919-4.919 1.266-.057 1.645-.069 4.849-.069zM12 0C8.741 0 8.333.014 7.053.072 2.695.272.273 2.69.073 7.052.014 8.333 0 8.741 0 12c0 3.259.014 3.668.072 4.948.2 4.358 2.618 6.78 6.98 6.98C8.333 23.986 8.741 24 12 24c3.259 0 3.668-.014 4.948-.072 4.354-.2 6.782-2.618 6.979-6.98.059-1.28.073-1.689.073-4.948 0-3.259-.014-3.667-.072-4.947-.196-4.354-2.617-6.78-6.979-6.98C15.668.014 15.259 0 12 0zm0 5.838a6.162 6.162 0 100 12.324 6.162 6.162 0 000-12.324zM12 16a4 4 0 110-8 4 4 0 010 8zm6.406-11.845a1.44 1.44 0 100 2.881 1.44 1.44 0 000-2.881z"/></svg>';
            var igText = document.createElement("span");
            igText.textContent = "@" + String(instagram).replace(/^@/, "");
            ig.appendChild(igText);
            container.appendChild(ig);
        }

        if (facebook) {
            var fb = document.createElement("span");
            fb.className = "social-item facebook";
            fb.innerHTML = '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M22.675 0h-21.35C.597 0 0 .597 0 1.326v21.348C0 23.403.597 24 1.326 24H12.82v-9.294H9.692v-3.622h3.128V8.413c0-3.1 1.893-4.788 4.659-4.788 1.325 0 2.463.099 2.795.143v3.24l-1.918.001c-1.504 0-1.795.715-1.795 1.763v2.313h3.587l-.467 3.622h-3.12V24h6.116c.73 0 1.323-.597 1.323-1.326V1.326C24 .597 23.403 0 22.675 0z"/></svg>';
            var fbText = document.createElement("span");
            fbText.textContent = String(facebook).replace(/^https?:\/\/(www\.)?facebook\.com\//i, "");
            fb.appendChild(fbText);
            container.appendChild(fb);
        }

        if (tiktok) {
            var tt = document.createElement("span");
            tt.className = "social-item tiktok";
            tt.innerHTML = '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M19.59 6.69a4.83 4.83 0 01-3.77-4.25V2h-3.45v13.67a2.89 2.89 0 01-5.2 1.74 2.89 2.89 0 012.31-4.64 2.93 2.93 0 01.88.13V9.4a6.84 6.84 0 00-1-.05A6.33 6.33 0 005 20.1a6.34 6.34 0 0010.86-4.43v-7a8.16 8.16 0 004.77 1.52v-3.4a4.85 4.85 0 01-1-.1z"/></svg>';
            var ttText = document.createElement("span");
            ttText.textContent = "@" + String(tiktok).replace(/^@/, "");
            tt.appendChild(ttText);
            container.appendChild(tt);
        }
    }

    /* ---------------------------------------------------------------------
       Videos
       --------------------------------------------------------------------- */

    function normalizeVideoItem(value, scheduled) {
        var url = value;
        var title = "";
        if (value && typeof value === "object") {
            url = value.url || value.src || value.value || "";
            title = value.title || value.name || "";
        }
        if (!url) return null;
        var raw = String(url).trim();
        var youtubeId = extractYoutubeId(raw);
        return {
            raw: raw,
            url: driveToDirect(raw),
            kind: youtubeId ? "youtube" : "direct",
            id: youtubeId,
            title: title,
            scheduled: !!scheduled
        };
    }

    function fallbackPlaylist(keywords) {
        var text = String(keywords || "").toLowerCase();
        if (text.indexOf("food") !== -1 || text.indexOf("restaurant") !== -1 || text.indexOf("comida") !== -1) {
            return ["https://www.youtube.com/watch?v=aqz-KE-bpKQ"];
        }
        if (text.indexOf("coffee") !== -1 || text.indexOf("cafe") !== -1 || text.indexOf("jazz") !== -1) {
            return ["https://www.youtube.com/watch?v=LXb3EKWsInQ"];
        }
        return [
            "https://www.youtube.com/watch?v=LXb3EKWsInQ",
            "https://www.youtube.com/watch?v=aqz-KE-bpKQ",
            "https://www.youtube.com/watch?v=eRsGyueVLvQ"
        ];
    }

    function buildQueue(playlist, scheduled, data) {
        state.lastPlaylist = Array.isArray(playlist) ? playlist : [];
        state.lastScheduled = Array.isArray(scheduled) ? scheduled : [];

        // Mientras hay un video elegido desde el control remoto no se toca la cola.
        if (state.manualOverride) {
            return;
        }

        var queue = [];

        state.lastScheduled.forEach(function (entry) {
            var item = normalizeVideoItem(entry, true);
            if (item) queue.push(item);
        });

        state.lastPlaylist.forEach(function (entry) {
            var item = normalizeVideoItem(entry, false);
            if (item) queue.push(item);
        });

        if (!queue.length && data.google_drive_link && data.video_source !== "youtube") {
            var driveItem = normalizeVideoItem(data.google_drive_link, false);
            if (driveItem) queue.push(driveItem);
        }

        // Sin contenido configurado no se inventan videos: se muestra la pantalla
        // de respaldo con la información del negocio.

        var signature = JSON.stringify(queue.map(function (item) {
            return item.kind + ":" + (item.id || item.url);
        }));

        if (signature === state.queueSignature) {
            setupAdFrequency(data);
            return;
        }

        state.queue = queue;
        state.queueSignature = signature;
        state.videoIndex = 0;
        state.failedVideos = {};
        playCurrent();
        setupAdFrequency(data);
    }

    function playCurrent() {
        if (!state.queue.length) {
            showFallback();
            return;
        }
        var item = state.queue[state.videoIndex % state.queue.length];
        if (!item) {
            showFallback();
            return;
        }

        console.log("VScreenS play:", state.videoIndex, item.kind, item.id || item.url, item.scheduled ? "PROGRAMADO" : "");

        if (state.failedVideos[item.kind + ":" + (item.id || item.url)]) {
            nextVideo();
            return;
        }

        state.currentItem = item;
        state.currentKind = item.kind;
        updateVideoBadge(item);

        if (item.kind === "youtube") {
            playYoutube(item);
        } else {
            playDirect(item);
        }
    }

    function nextVideo() {
        state.cuedId = null;
        if (state.cueTimer) {
            window.clearInterval(state.cueTimer);
            state.cueTimer = null;
        }
        if (!state.queue.length) {
            showFallback();
            return;
        }
        var attempts = 0;
        do {
            state.videoIndex = (state.videoIndex + 1) % state.queue.length;
            attempts += 1;
            var candidate = state.queue[state.videoIndex];
            if (!candidate) break;
            if (!state.failedVideos[candidate.kind + ":" + (candidate.id || candidate.url)]) {
                playCurrent();
                return;
            }
        } while (attempts < state.queue.length);

        showFallback();
    }

    /* --- YouTube --------------------------------------------------------- */

    function loadYouTubeApi(callback) {
        if (window.YT && window.YT.Player) {
            callback();
            return;
        }

        var existing = document.getElementById("youtube-iframe-api");
        if (!existing) {
            var tag = document.createElement("script");
            tag.id = "youtube-iframe-api";
            tag.src = "https://www.youtube.com/iframe_api";
            document.head.appendChild(tag);
        }

        if (!window.__vsYtCallbacks) window.__vsYtCallbacks = [];
        window.__vsYtCallbacks.push(callback);

        window.onYouTubeIframeAPIReady = function () {
            var callbacks = window.__vsYtCallbacks || [];
            window.__vsYtCallbacks = [];
            callbacks.forEach(function (fn) {
                try {
                    fn();
                } catch (err) {
                    console.warn("YT callback error", err);
                }
            });
        };
    }

    function ensurePlayer(callback) {
        if (state.playerReady && state.player) {
            callback();
            return;
        }

        loadYouTubeApi(function () {
            if (state.playerReady && state.player) {
                callback();
                return;
            }
            if (state.playerLoading) {
                window.setTimeout(function () {
                    ensurePlayer(callback);
                }, 300);
                return;
            }
            state.playerLoading = true;
            var initialId = (state.currentItem && state.currentItem.kind === "youtube") ? state.currentItem.id : undefined;
            state.playerInitialId = initialId || null;

            state.player = new window.YT.Player("yt-player", {
                width: "100%",
                height: "100%",
                videoId: initialId,
                playerVars: {
                    autoplay: 1,
                    controls: 0,
                    disablekb: 1,
                    enablejsapi: 1,
                    fs: 0,
                    iv_load_policy: 3,
                    modestbranding: 1,
                    playsinline: 1,
                    rel: 0,
                    origin: window.location.origin
                },
                events: {
                    onReady: function (event) {
                        state.playerReady = true;
                        state.playerLoading = false;
                        state.playerFresh = true;
                        try {
                            event.target.setVolume(100);
                            if (state.muted) {
                                event.target.mute();
                            } else {
                                event.target.unMute();
                            }
                            event.target.playVideo();
                            window.setTimeout(function () {
                                try {
                                    if (!state.muted && event.target.getPlayerState && event.target.getPlayerState() !== 1) {
                                        event.target.mute();
                                        event.target.playVideo();
                                        state.muted = true;
                                        syncSoundButtonUI();
                                        showSoundToggle();
                                    }
                                } catch (e) { }
                            }, 1400);
                        } catch (err) {
                            console.warn("YT ready play error", err);
                        }
                        syncSoundButtonUI();
                        callback();
                    },
                    onStateChange: function (event) {
                        if (event.data === window.YT.PlayerState.PLAYING) {
                            hideFallback();
                            showSoundToggle();
                        }
                        if (event.data === window.YT.PlayerState.ENDED) {
                            if (state.inPriority) {
                                finishPriority();
                            } else if (state.manualOverride) {
                                clearYoutubeOverride();
                            } else if (playCuedNext()) {
                                // El siguiente video ya está cargado: arranca al instante.
                            } else {
                                nextVideo();
                            }
                        }
                    },
                    onError: function (event) {
                        console.warn("YouTube error", event && event.data);
                        if (state.inPriority) {
                            finishPriority();
                            return;
                        }
                        if (state.manualOverride) {
                            clearYoutubeOverride();
                            return;
                        }
                        var item = state.currentItem;
                        if (item) {
                            state.failedVideos[item.kind + ":" + (item.id || item.url)] = true;
                        }
                        window.setTimeout(nextVideo, 700);
                    }
                }
            });
        });
    }

    function scheduleNextCue() {
        // Desactivado intencionalmente: llamar cueVideoById() sobre el mismo player activo
        // de YouTube detiene el video actual y congela la pantalla en estado CUED.
        if (state.cueTimer) {
            window.clearInterval(state.cueTimer);
            state.cueTimer = null;
        }
        state.cuedId = null;
    }

    function playCuedNext() {
        if (!state.cuedId || state.queue.length < 2 || !state.playerReady || !state.player) {
            return false;
        }
        var next = state.queue[(state.videoIndex + 1) % state.queue.length];
        if (!next || next.id !== state.cuedId) {
            return false;
        }
        state.videoIndex = (state.videoIndex + 1) % state.queue.length;
        state.currentItem = next;
        state.cuedId = null;
        updateVideoBadge(next);
        try {
            state.player.playVideo();
            return true;
        } catch (err) {
            return false;
        }
    }

    function playYoutube(item) {
        ensurePlayer(function () {
            if (!item.id) {
                nextVideo();
                return;
            }

            var start = function () {
                var filePlayer = $("file-player");
                if (filePlayer) {
                    filePlayer.pause();
                    filePlayer.classList.add("hidden");
                }
                var yt = $("yt-player");
                if (yt) yt.classList.remove("hidden");

                // Si el reproductor nació con este mismo video, no hace falta
                // volver a cargarlo: basta con reproducirlo.
                if (state.playerFresh && state.playerInitialId && item.id === state.playerInitialId) {
                    state.playerFresh = false;
                    try {
                        state.player.playVideo();
                        hideFallback();
                        showSoundToggle();
                    } catch (err) {
                        console.warn("YouTube initial play error", err);
                    }
                    return;
                }

                try {
                    state.player.loadVideoById({ videoId: item.id });
                    state.player.playVideo();
                    hideFallback();
                    showSoundToggle();
                    scheduleNextCue();
                } catch (err) {
                    console.warn("YouTube load error", err);
                    nextVideo();
                }
            };

            // El primer loadVideoById justo después de onReady falla en algunos
            // navegadores de TV. Se le da un instante al reproductor para
            // terminar de inicializarse.
            if (state.playerFresh) {
                state.playerFresh = false;
                window.setTimeout(start, 800);
            } else {
                start();
            }
        });
    }

    function playDirect(item) {
        var filePlayer = $("file-player");
        var yt = $("yt-player");
        if (yt) yt.classList.add("hidden");
        if (!filePlayer) return;

        filePlayer.classList.remove("hidden");
        filePlayer.muted = state.muted;
        filePlayer.volume = 1;
        filePlayer.loop = state.queue.length === 1;
        filePlayer.src = item.url;
        filePlayer.onerror = function () {
            state.failedVideos[item.kind + ":" + (item.id || item.url)] = true;
            nextVideo();
        };
        filePlayer.onended = function () {
            if (state.inPriority) {
                finishPriority();
            } else {
                nextVideo();
            }
        };
        var promise = filePlayer.play();
        if (promise && promise.catch) {
            promise.catch(function () {
                if (!state.muted) {
                    state.muted = true;
                    filePlayer.muted = true;
                    syncSoundButtonUI();
                    showSoundToggle();
                    filePlayer.play().catch(function () {
                        showFallback();
                    });
                } else {
                    showFallback();
                }
            });
        }
        syncSoundButtonUI();
        hideFallback();
    }

    function updateVideoBadge(item) {
        var badge = $("video-badge");
        if (!badge) return;
        var label = item.title || (item.scheduled ? "Contenido programado" : "VScreenS TV");
        badge.innerHTML = "";
        if (item.scheduled) {
            var strong = document.createElement("strong");
            strong.textContent = "PROGRAMADO · ";
            badge.appendChild(strong);
        }
        badge.appendChild(document.createTextNode(label));
        badge.classList.remove("hidden");
    }

    function showFallback() {
        var fallback = $("video-fallback");
        if (fallback) fallback.classList.remove("hidden");
        var badge = $("video-badge");
        if (badge) badge.classList.add("hidden");
        startFallbackRotation();
    }

    function hideFallback() {
        var fallback = $("video-fallback");
        if (fallback) fallback.classList.add("hidden");
        if (state.fallbackTimer) {
            window.clearInterval(state.fallbackTimer);
            state.fallbackTimer = null;
        }
    }

    function startFallbackRotation() {
        if (state.fallbackTimer) return;
        state.fallbackTimer = window.setInterval(function () {
            if (!state.sidebarSlides.length) return;
            state.fallbackIndex = (state.fallbackIndex + 1) % state.sidebarSlides.length;
            var slide = state.sidebarSlides[state.fallbackIndex];
            var title = $("fallback-title");
            var sub = $("fallback-sub");
            if (title && slide.title) title.textContent = slide.title;
            if (sub && (slide.sub || slide.price)) sub.textContent = slide.sub || slide.price;
        }, 6000);
    }

    function showSoundToggle() {
        var button = $("sound-toggle");
        if (!button) return;
        button.classList.add("is-visible");
        if (state.soundHideTimer) window.clearTimeout(state.soundHideTimer);
        state.soundHideTimer = window.setTimeout(function () {
            button.classList.remove("is-visible");
        }, 12000);
    }

    function syncSoundButtonUI() {
        var button = $("sound-toggle");
        if (!button) return;
        var label = button.querySelector(".sound-label");
        if (state.muted) {
            button.classList.remove("is-on");
            if (label) label.textContent = "Activar sonido";
        } else {
            button.classList.add("is-on");
            if (label) label.textContent = "Sonido activo";
        }
    }

    function toggleSound() {
        var filePlayer = $("file-player");
        try {
            if (state.muted) {
                if (state.player && state.playerReady) {
                    state.player.unMute();
                    state.player.setVolume(100);
                }
                if (filePlayer) filePlayer.muted = false;
                state.muted = false;
            } else {
                if (state.player && state.playerReady) {
                    state.player.mute();
                }
                if (filePlayer) filePlayer.muted = true;
                state.muted = true;
            }
        } catch (err) {
            console.warn("Sound toggle error", err);
        }
        syncSoundButtonUI();
        showSoundToggle();
    }

    /* --- Prioridad / anuncios ------------------------------------------- */

    function handlePriority(url) {
        if (!url) {
            if (state.priorityUrl) {
                state.priorityUrl = null;
                state.inPriority = false;
                hideOverlay("priority-overlay");
                resumeNormalVideo();
            }
            return;
        }
        if (url === state.priorityUrl && state.inPriority) return;
        state.priorityUrl = url;

        if (isYoutubeUrl(url)) {
            var id = extractYoutubeId(url);
            if (!id) return;
            state.priorityReturnItem = state.currentItem;
            state.inPriority = true;
            ensurePlayer(function () {
                state.player.loadVideoById({ videoId: id });
                state.player.playVideo();
            });
        } else {
            var overlay = $("priority-overlay");
            var video = $("priority-video");
            if (!overlay || !video) return;
            state.inPriority = true;
            video.muted = state.muted;
            video.src = driveToDirect(url);
            overlay.classList.remove("hidden");
            var cleanup = function () {
                overlay.classList.add("hidden");
                video.pause();
                state.inPriority = false;
                state.priorityUrl = null;
                resumeNormalVideo();
            };
            video.onended = cleanup;
            video.onerror = cleanup;
            var promise = video.play();
            if (promise && promise.catch) {
                promise.catch(function () {
                    video.muted = true;
                    var retry = video.play();
                    if (retry && retry.catch) retry.catch(cleanup);
                });
            }
        }
    }

    function finishPriority() {
        state.inPriority = false;
        state.priorityUrl = null;
        resumeNormalVideo();
    }

    function resumeNormalVideo() {
        state.videoIndex = 0;
        playCurrent();
    }

    function setupAdFrequency(data) {
        if (state.adTimer) {
            window.clearInterval(state.adTimer);
            state.adTimer = null;
        }
        var adUrl = data.priority_content_url || data.google_drive_link;
        if (!adUrl || !data.ad_frequency) return;
        var seconds = Number(data.ad_frequency);
        if (!isFinite(seconds) || seconds < 10) return;
        state.adTimer = window.setInterval(function () {
            if (state.inPriority) return;
            handlePriority(adUrl);
        }, seconds * 1000);
    }

    /* ---------------------------------------------------------------------
       Alertas
       --------------------------------------------------------------------- */

    function handleAlert(alert) {
        if (!alert) {
            hideAlert();
            return;
        }
        var id = alert.id || (alert.subject + "|" + alert.body);
        if (id === state.activeAlertId) return;
        state.activeAlertId = id;
        showAlert(alert);
    }

    function showAlert(alert) {
        var rail = $("alert-rail");
        var subject = $("alert-subject");
        var body = $("alert-body");
        var progress = $("alert-progress-bar");
        if (!rail || !body) return;

        subject.textContent = alert.subject || "AVISO IMPORTANTE";
        body.textContent = alert.body || "";
        rail.classList.add("is-visible");

        var duration = Number(alert.duration || 20);
        if (!isFinite(duration) || duration < 5) duration = 20;

        if (progress) {
            progress.classList.remove("is-running");
            progress.style.animationDuration = "";
            void progress.offsetWidth;
            progress.style.animationDuration = duration + "s";
            progress.classList.add("is-running");
        }

        if (state.alertTimer) window.clearTimeout(state.alertTimer);
        state.alertTimer = window.setTimeout(function () {
            hideAlert();
        }, duration * 1000);

        // Confirmar lectura en Odoo para que la alerta no se repita en próximos ciclos
        if (!previewCompanyId && alert.id) {
            fetch(API_URL + "/devices/" + encodeURIComponent(state.uuid) + "/ack-alert", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ alert_id: alert.id })
            }).catch(function () { });
        }
    }

    function hideAlert() {
        var rail = $("alert-rail");
        if (rail) rail.classList.remove("is-visible");
        if (state.alertTimer) {
            window.clearTimeout(state.alertTimer);
            state.alertTimer = null;
        }
    }

    /* ---------------------------------------------------------------------
       Ping / identificación
       --------------------------------------------------------------------- */

    function handlePing(data) {
        if (!data.ping_command) return;
        var now = Date.now();
        if (now - state.lastPingAt < 10000) return;
        state.lastPingAt = now;

        var overlay = $("ping-overlay");
        var name = $("ping-device-name");
        if (name) name.textContent = data.name || state.uuid;
        if (!overlay) return;
        overlay.classList.remove("hidden");
        if (state.pingTimer) window.clearTimeout(state.pingTimer);
        state.pingTimer = window.setTimeout(function () {
            overlay.classList.add("hidden");
        }, 9000);
    }

    /* ---------------------------------------------------------------------
       Overlays de registro / suspensión
       --------------------------------------------------------------------- */

    function hideOverlay(id) {
        var el = $(id);
        if (el) el.classList.add("hidden");
    }

    function showSuspended(reason) {
        if (previewCompanyId) return;
        // Pausar reproducción y timers para no consumir audio/ancho de banda detrás del telón
        try { if (state.player && state.playerReady) state.player.pauseVideo(); } catch (e) { }
        var filePlayer = $("file-player");
        if (filePlayer) { try { filePlayer.pause(); } catch (e) { } }
        var prioVideo = $("priority-video");
        if (prioVideo) { try { prioVideo.pause(); } catch (e) { } }
        if (state.slideTimer) { window.clearInterval(state.slideTimer); state.slideTimer = null; }
        if (state.adTimer) { window.clearInterval(state.adTimer); state.adTimer = null; }
        if (state.fallbackTimer) { window.clearInterval(state.fallbackTimer); state.fallbackTimer = null; }

        hideOverlay("registration-overlay");
        var el = $("kill-switch");
        if (el) {
            if (reason) {
                var desc = el.querySelector("p");
                if (desc) desc.textContent = reason;
            }
            el.classList.remove("hidden");
        }
        var splash = $("splash");
        if (splash) splash.classList.add("is-hidden");
    }

    function showRegistration(message) {
        if (previewCompanyId) return;
        var overlay = $("registration-overlay");
        var uuid = $("device-uuid-display");
        var status = $("reg-status");
        if (!overlay) return;

        overlay.classList.remove("hidden");
        if (uuid) uuid.textContent = state.uuid;
        if (status && message) {
            status.textContent = message;
            status.className = "reg-status";
        } else if (status && (!status.textContent || status.textContent.indexOf("Sin conexión") !== -1 || status.textContent.indexOf("Reconectando") !== -1)) {
            status.textContent = "Esperando vinculación…";
            status.className = "reg-status";
        }

        var splash = $("splash");
        if (splash) splash.classList.add("is-hidden");
        var codeInput = $("reg-code-input");
        if (codeInput && document.activeElement !== codeInput) {
            window.setTimeout(function () { codeInput.focus(); }, 150);
        }
    }

    function submitRegistration() {
        var input = $("reg-code-input");
        var status = $("reg-status");
        if (!input) return;
        var code = String(input.value || "").replace(/\D/g, "");
        if (code.length !== 6) {
            setRegisterStatus("Ingresa los 6 dígitos del código.", true);
            return;
        }

        setRegisterStatus("Vinculando pantalla…", false);

        fetch(API_URL + "/devices/validate-code?code=" + encodeURIComponent(code) + "&device_uuid=" + encodeURIComponent(state.uuid), {
            method: "POST"
        })
            .then(function (response) {
                return response.json().catch(function () {
                    return {};
                }).then(function (data) {
                    return { ok: response.ok, status: response.status, data: data };
                });
            })
            .then(function (result) {
                if (result.ok) {
                    setRegisterStatus("¡Pantalla vinculada! Cargando contenido…", false, true);
                    hideOverlay("registration-overlay");
                    state.lastUpdated = null;
                    state.config = null;
                    fetchConfig();
                    return;
                }
                if (result.data && result.data.detail === "DEVICE_BLOCKED_FREE_TRIAL_USED") {
                    setRegisterStatus("Esta pantalla ya utilizó su prueba gratuita. Suscríbete para continuar.", true);
                } else {
                    setRegisterStatus("Código inválido o expirado. Intenta de nuevo.", true);
                }
            })
            .catch(function () {
                setRegisterStatus("No se pudo conectar con el servidor. Reintenta.", true);
            });
    }

    function setRegisterStatus(text, isError, isOk) {
        var status = $("reg-status");
        if (!status) return;
        status.textContent = text;
        status.className = "reg-status" + (isError ? " is-error" : "") + (isOk ? " is-ok" : "");
    }

    /* ---------------------------------------------------------------------
       Actualizaciones en vivo desde el panel (iframe)
       --------------------------------------------------------------------- */

    function handlePreviewMessage(payload) {
        if (!payload || typeof payload !== "object") return;
        var merged = Object.assign({}, state.config || {}, payload);
        ["design_settings", "sidebar_content", "bottom_bar_content", "video_playlist", "scheduled_videos", "menus"].forEach(function (key) {
            if (merged[key] && typeof merged[key] === "string") {
                merged[key] = parseJson(merged[key], key === "bottom_bar_content" ? {} : []);
            }
        });
        applyConfig(merged, true);
    }

    /* ---------------------------------------------------------------------
       Arranque
       --------------------------------------------------------------------- */

    /* ---------------------------------------------------------------------
       Control remoto: cambiar temporalmente el video de YouTube
       --------------------------------------------------------------------- */
    function showYoutubeControl() {
        if (!state.config || !state.config.allow_youtube_control) {
            return;
        }
        var overlay = $("yt-control");
        if (!overlay) return;
        overlay.classList.remove("hidden");
        var input = $("yt-control-input");
        if (input) {
            input.value = "";
            input.focus();
        }
        var msg = $("yt-control-msg");
        if (msg) msg.textContent = "";
    }

    function hideYoutubeControl() {
        var overlay = $("yt-control");
        if (overlay) overlay.classList.add("hidden");
    }

    function scheduleOverrideTimeout() {
        if (state.overrideTimer) {
            window.clearTimeout(state.overrideTimer);
        }
        var minutes = Number(state.config && state.config.youtube_control_minutes) || 30;
        state.overrideTimer = window.setTimeout(clearYoutubeOverride, Math.max(1, minutes) * 60000);
    }

    function playYoutubeOverride() {
        if (!state.config || !state.config.allow_youtube_control) {
            hideYoutubeControl();
            return;
        }
        var input = $("yt-control-input");
        var value = input ? input.value.trim() : "";
        var id = extractYoutubeId(value);
        var msg = $("yt-control-msg");
        if (!id) {
            if (msg) msg.textContent = "Enlace de YouTube no válido.";
            return;
        }
        var item = {
            raw: value,
            url: value,
            kind: "youtube",
            id: id,
            title: "Control remoto",
            scheduled: false
        };
        state.manualOverride = item;
        state.currentItem = item;
        hideYoutubeControl();
        hideFallback();
        playYoutube(item);
        scheduleOverrideTimeout();
    }

    function clearYoutubeOverride() {
        var hadOverride = !!state.manualOverride;
        state.manualOverride = null;
        state.cuedId = null;
        if (state.cueTimer) {
            window.clearInterval(state.cueTimer);
            state.cueTimer = null;
        }
        if (state.overrideTimer) {
            window.clearTimeout(state.overrideTimer);
            state.overrideTimer = null;
        }
        hideYoutubeControl();
        if (hadOverride && state.config) {
            state.queueSignature = "";
            buildQueue(state.lastPlaylist, state.lastScheduled, state.config);
        }
    }

    function bindEvents() {
        updateClocks();
        window.setInterval(updateClocks, 1000);

        var sound = $("sound-toggle");
        if (sound) sound.addEventListener("click", toggleSound);

        var submit = $("reg-submit-btn");
        if (submit) submit.addEventListener("click", submitRegistration);

        var input = $("reg-code-input");
        if (input) {
            input.addEventListener("keydown", function (event) {
                if (event.key === "Enter") submitRegistration();
            });
        }

        var ytPlay = $("yt-control-play");
        if (ytPlay) ytPlay.addEventListener("click", playYoutubeOverride);
        var ytBack = $("yt-control-back");
        if (ytBack) ytBack.addEventListener("click", clearYoutubeOverride);
        var ytInput = $("yt-control-input");
        if (ytInput) {
            ytInput.addEventListener("keydown", function (event) {
                if (event.key === "Enter") playYoutubeOverride();
                if (event.key === "Escape") hideYoutubeControl();
            });
        }

        document.addEventListener("click", function () {
            showSoundToggle();
        }, { once: true });

        window.addEventListener("message", function (event) {
            if (!previewCompanyId) return;
            var origin = String(event.origin || "");
            var allowedOrigin = origin === window.location.origin ||
                /^https:\/\/([a-z0-9-]+\.)?inverpave\.com$/i.test(origin) ||
                /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/i.test(origin);
            if (!allowedOrigin) return;
            var message = event.data;
            if (message && message.type === "PREVIEW_UPDATE") {
                handlePreviewMessage(message.payload);
            }
        });

        window.addEventListener("online", function () {
            state.lastUpdated = null;
            state.failedVideos = {};
            state.queueSignature = "";
            fetchConfig();
        });

        /* ========================================================================
           CONTROL REMOTO DE TV - TODAS LAS OPCIONES NATIVAS
           Permite control completo desde el control remoto del TV/dispositivo
           sin interferir con la escritura en inputs/modales
           ======================================================================== */
        var navIndex = -1;
        var navItems = [];

        function isTypingTarget(el) {
            if (!el) return false;
            var tag = (el.tagName || "").toUpperCase();
            return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || el.isContentEditable;
        }

        function refreshNavItems() {
            var scope = document;
            var regOverlay = $("registration-overlay");
            var ytModal = $("yt-control-modal");
            if (regOverlay && !regOverlay.classList.contains("hidden")) {
                scope = regOverlay;
            } else if (ytModal && !ytModal.classList.contains("hidden")) {
                scope = ytModal;
            }
            navItems = Array.from(scope.querySelectorAll(
                "button, a, input, select, [role='button'], [tabindex='0']"
            )).filter(function (el) {
                var r = el.getBoundingClientRect();
                return r.width > 0 && r.height > 0 && !el.disabled;
            });
        }

        function navigateNav(delta) {
            refreshNavItems();
            if (navItems.length === 0) return;
            var cur = navItems.indexOf(document.activeElement);
            navIndex = cur >= 0 ? (cur + delta + navItems.length) % navItems.length : 0;
            var el = navItems[navIndex];
            if (el) {
                el.focus();
                el.scrollIntoView({ behavior: "smooth", block: "center" });
            }
        }

        function activateNav() {
            var el = document.activeElement;
            if (!el || el === document.body) {
                if (navItems.length === 0 || navIndex < 0) return;
                el = navItems[navIndex];
            }
            if (el && typeof el.click === "function") {
                el.click();
            }
        }

        window.addEventListener("keydown", function (e) {
            var code = e.code || "";
            var key = (e.key || "").toLowerCase();
            var typing = isTypingTarget(document.activeElement);

            // Si el foco está en un campo de texto, solo permitir flechas arriba/abajo para cambiar de control
            if (typing) {
                if (code === "ArrowDown" || key === "arrowdown") {
                    e.preventDefault();
                    navigateNav(1);
                } else if (code === "ArrowUp" || key === "arrowup") {
                    e.preventDefault();
                    navigateNav(-1);
                } else if (code === "Escape" || key === "escape") {
                    document.activeElement.blur();
                }
                return;
            }

            /* ---------- Navegación con flechas ---------- */
            if (code === "ArrowDown" || key === "arrowdown") {
                e.preventDefault();
                navigateNav(1);
                return;
            }
            if (code === "ArrowUp" || key === "arrowup") {
                e.preventDefault();
                navigateNav(-1);
                return;
            }
            if (code === "ArrowRight" || key === "arrowright") {
                e.preventDefault();
                if (state.player && state.playerReady) {
                    nextVideo();
                } else {
                    navigateNav(1);
                }
                return;
            }
            if (code === "ArrowLeft" || key === "arrowleft") {
                e.preventDefault();
                if (state.player && state.playerReady) {
                    if (state.queue.length) {
                        state.videoIndex = (state.videoIndex - 1 + state.queue.length) % state.queue.length;
                        playCurrent();
                    }
                } else {
                    navigateNav(-1);
                }
                return;
            }

            /* ---------- Selección / Enter ---------- */
            if (code === "Enter" || key === "enter" || code === "NumpadEnter") {
                e.preventDefault();
                activateNav();
                return;
            }

            /* ---------- Retroceso / Back ---------- */
            if (code === "Escape" || key === "escape" || key === "back") {
                e.preventDefault();
                var ytModal = $("yt-control-modal");
                if (ytModal && !ytModal.classList.contains("hidden")) {
                    ytModal.classList.add("hidden");
                    return;
                }
                return;
            }

            /* ---------- Inicio / Home ---------- */
            if (code === "Home" || key === "home") {
                e.preventDefault();
                if (previewCompanyId) {
                    window.location.href = window.location.origin + "/?preview=" + encodeURIComponent(previewCompanyId) +
                        (previewToken ? "&pt=" + encodeURIComponent(previewToken) : "");
                } else {
                    window.location.href = window.location.origin + "/";
                }
                return;
            }

            /* ---------- Búsqueda ---------- */
            if (code === "Search" || key === "search" || (e.ctrlKey && key === "f")) {
                e.preventDefault();
                if (state.config && state.config.allow_youtube_control) {
                    showYoutubeControl();
                }
                return;
            }

            /* ---------- Búsqueda por voz (tecla dedicada Mic/VoiceSearch) ---------- */
            if (code === "VoiceSearch" || key === "voicesearch") {
                e.preventDefault();
                if (typeof webkitSpeechRecognition !== "undefined" || typeof SpeechRecognition !== "undefined") {
                    var SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
                    var rec = new SpeechRecognition();
                    rec.lang = "es-VE";
                    rec.interimResults = false;
                    rec.maxAlternatives = 1;
                    rec.onresult = function (event) {
                        var texto = event.results[0][0].transcript;
                        var inp = document.querySelector("input[type='search'], input[placeholder*='buscar' i]");
                        if (inp) { inp.value = texto; inp.dispatchEvent(new Event("input", { bubbles: true })); }
                    };
                    rec.onerror = function () { console.warn("Error de reconocimiento de voz"); };
                    rec.start();
                } else {
                    console.warn("SpeechRecognition no disponible en este navegador");
                }
                return;
            }

            /* ---------- Control de volumen ---------- */
            if (code === "VolumeUp" || key === "volumeup") {
                e.preventDefault();
                try {
                    if (state.player && state.playerReady) {
                        var vol = state.player.getVolume();
                        state.player.setVolume(Math.min(100, vol + 10));
                    }
                } catch (err) { console.warn("Volumen error", err); }
                return;
            }
            if (code === "VolumeDown" || key === "volumedown") {
                e.preventDefault();
                try {
                    if (state.player && state.playerReady) {
                        var vol = state.player.getVolume();
                        state.player.setVolume(Math.max(0, vol - 10));
                    }
                } catch (err) { console.warn("Volumen error", err); }
                return;
            }
            if (code === "VolumeMute" || key === "volumemute") {
                e.preventDefault();
                try {
                    if (state.player && state.playerReady) {
                        state.player.isMuted() ? state.player.unMute() : state.player.mute();
                    }
                } catch (err) { console.warn("Mute error", err); }
                return;
            }

            /* ---------- Control de reproducción YouTube ---------- */
            if (!state.player || !state.playerReady) return;

            // Siguiente video
            if (code === "MediaNextTrack" || key === "next") {
                e.preventDefault();
                nextVideo();
                return;
            }
            // Video anterior
            if (code === "MediaPreviousTrack" || key === "previous") {
                e.preventDefault();
                if (state.queue.length) {
                    state.videoIndex = (state.videoIndex - 1 + state.queue.length) % state.queue.length;
                    playCurrent();
                }
                return;
            }
            // Play / Pausa
            if (code === "MediaPlayPause" || key === "play" || key === " ") {
                e.preventDefault();
                try {
                    var ps = state.player.getPlayerState();
                    if (ps === 1) { state.player.pauseVideo(); }
                    else if (ps === 2) { state.player.playVideo(); }
                    else if (ps === -1 || ps === 5) { state.player.playVideo(); }
                } catch (err) { console.warn("YT play/pause error", err); }
                return;
            }
            // Detener
            if (code === "MediaStop" || key === "stop") {
                e.preventDefault();
                try { state.player.stopVideo(); } catch (err) { console.warn("YT stop error", err); }
                return;
            }
            // Teclas numéricas 1-9 para ir a video de la cola
            var num = parseInt(key);
            if (!isNaN(num) && num >= 1 && num <= 9 && state.queue && state.queue.length) {
                e.preventDefault();
                var idx = num - 1;
                if (idx < state.queue.length) {
                    state.videoIndex = idx;
                    playCurrent();
                }
                return;
            }
            // Tecla 0 para video al final
            if (key === "0" && state.queue && state.queue.length) {
                e.preventDefault();
                state.videoIndex = state.queue.length - 1;
                playCurrent();
                return;
            }
        });
    }

    function init() {
        window.__VScreenS = state;
        bindEvents();
        fetchConfig();
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
