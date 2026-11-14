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
    var DEVICE_KEY = "device_uuid";

    var state = {
        uuid: getDeviceUuid(),
        config: null,
        lastUpdated: null,
        sidebarSlides: [],
        slideIndex: 0,
        slideTimer: null,
        tickerTimer: null,
        alertTimer: null,
        activeAlertId: null,
        queue: [],
        queueSignature: "",
        videoIndex: 0,
        failedVideos: {},
        player: null,
        playerReady: false,
        playerLoading: false,
        playerFresh: false,
        currentItem: null,
        currentKind: null,
        muted: true,
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
        var now = new Date();
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
       Carga de configuración
       --------------------------------------------------------------------- */

    function configUrl() {
        var base = previewCompanyId
            ? API_URL + "/companies/" + encodeURIComponent(previewCompanyId) + "/preview-config"
            : API_URL + "/devices/" + encodeURIComponent(state.uuid) + "/config";
        return base + (base.indexOf("?") === -1 ? "?" : "&") + "_t=" + Date.now();
    }

    function fetchConfig() {
        var url = configUrl();
        fetch(url, { cache: "no-store" })
            .then(function (response) {
                if (response.status === 404) {
                    if (!previewCompanyId) showRegistration();
                    return null;
                }
                if (!response.ok) throw new Error("HTTP " + response.status);
                return response.json();
            })
            .then(function (data) {
                if (!data) return;
                if (data.last_updated && data.last_updated === state.lastUpdated) {
                    handlePing(data);
                    return;
                }
                state.lastUpdated = data.last_updated || null;
                applyConfig(data, false);
            })
            .catch(function (error) {
                var fallbackSub = $("fallback-sub");
                if (fallbackSub && !state.config) fallbackSub.textContent = "Reconectando con VScreenS…";
                if (!state.config && !previewCompanyId) {
                    showRegistration("Reconectando con el servidor…");
                }
                console.warn("VScreenS config error:", error);
            })
            .then(function () {
                window.setTimeout(fetchConfig, 10000);
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
            showSuspended();
            return;
        }

        hideOverlay("kill-switch");

        applyTheme(data, design);
        applyBrand(data, design);
        buildSidebar(sidebarItems, menus, design);
        buildTicker(bottom, data, design);
        buildQueue(playlist, scheduled, data);
        handlePriority(data.priority_content_url || null);
        handleAlert(data.active_alert);
        handlePing(data);

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

        if (design.safety_margin !== undefined && design.safety_margin !== null) {
            root.style.setProperty("--safe", Number(design.safety_margin) + "vw");
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
                eyebrow: item.eyebrow || "",
                fontFamily: item.font_family || "",
                weight: item.weight || "",
                index: i
            };

            if (next && typeof next === "object" && next.type !== "image" && (next.value || next.text)) {
                var nextValue = String(next.value !== undefined ? next.value : next.text);
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
        var card = document.createElement("article");
        card.className = "promo-card" + (initial ? " is-entering" : " is-entering");

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
        }

        var counter = document.createElement("div");
        counter.className = "promo-index";
        counter.textContent = pad2((state.slideIndex % slides.length) + 1) + " / " + pad2(slides.length);
        card.appendChild(counter);

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

        var whatsapp = bottom.whatsapp || data.whatsapp;
        if (whatsapp) items.push("WhatsApp: " + whatsapp);

        var instagram = bottom.instagram || data.instagram;
        if (instagram) items.push("Instagram: @" + String(instagram).replace(/^@/, ""));

        var phone = data.phone;
        if (phone && String(phone) !== String(whatsapp || "")) items.push("Teléfono: " + phone);

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

        buildSocialPills(bottom, data);
    }

    function buildSocialPills(bottom, data) {
        var container = $("social-pill");
        if (!container) return;
        container.innerHTML = "";

        var whatsapp = bottom.whatsapp || data.whatsapp;
        var instagram = bottom.instagram || data.instagram;

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
        var queue = [];

        (Array.isArray(scheduled) ? scheduled : []).forEach(function (entry) {
            var item = normalizeVideoItem(entry, true);
            if (item) queue.push(item);
        });

        (Array.isArray(playlist) ? playlist : []).forEach(function (entry) {
            var item = normalizeVideoItem(entry, false);
            if (item) queue.push(item);
        });

        if (!queue.length && data.google_drive_link && data.video_source !== "youtube") {
            var driveItem = normalizeVideoItem(data.google_drive_link, false);
            if (driveItem) queue.push(driveItem);
        }

        if (!queue.length && data.video_source === "youtube") {
            fallbackPlaylist(data.filler_keywords).forEach(function (url) {
                var item = normalizeVideoItem(url, false);
                if (item) queue.push(item);
            });
        }

        if (!queue.length) {
            var fallback = normalizeVideoItem("https://www.youtube.com/watch?v=LXb3EKWsInQ", false);
            if (fallback) queue.push(fallback);
        }

        var signature = JSON.stringify(queue.map(function (item) {
            return item.kind + ":" + (item.id || item.url);
        }));

        if (signature === state.queueSignature) {
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
                            event.target.setVolume(70);
                            event.target.mute();
                            event.target.playVideo();
                        } catch (err) {
                            console.warn("YT ready play error", err);
                        }
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
                            } else {
                                nextVideo();
                            }
                        }
                    },
                    onError: function (event) {
                        console.warn("YouTube error", event && event.data);
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
        filePlayer.muted = true;
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
                showFallback();
            });
        }
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

    function toggleSound() {
        if (!state.player || !state.playerReady) return;
        var button = $("sound-toggle");
        try {
            if (state.muted) {
                state.player.unMute();
                state.player.setVolume(100);
                state.muted = false;
                if (button) {
                    button.classList.add("is-on");
                    button.querySelector(".sound-label").textContent = "Sonido activo";
                }
            } else {
                state.player.mute();
                state.muted = true;
                if (button) {
                    button.classList.remove("is-on");
                    button.querySelector(".sound-label").textContent = "Sonido";
                }
            }
        } catch (err) {
            console.warn("Sound toggle error", err);
        }
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
        if (url === state.priorityUrl) return;
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
            video.src = driveToDirect(url);
            overlay.classList.remove("hidden");
            var promise = video.play();
            if (promise && promise.catch) promise.catch(function () { });
            video.onended = function () {
                overlay.classList.add("hidden");
                video.pause();
                state.inPriority = false;
                resumeNormalVideo();
            };
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
        if (state.adTimer) window.clearInterval(state.adTimer);
        if (!data.google_drive_link || !data.ad_frequency) return;
        var seconds = Number(data.ad_frequency);
        if (!isFinite(seconds) || seconds < 10) return;
        state.adTimer = window.setInterval(function () {
            if (state.inPriority) return;
            handlePriority(data.google_drive_link);
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

    function showSuspended() {
        if (previewCompanyId) return;
        hideOverlay("registration-overlay");
        var el = $("kill-switch");
        if (el) el.classList.remove("hidden");
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
        } else if (status && !status.textContent) {
            status.textContent = "Esperando vinculación…";
        }

        var splash = $("splash");
        if (splash) splash.classList.add("is-hidden");
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

        document.addEventListener("click", function () {
            showSoundToggle();
        }, { once: true });

        window.addEventListener("message", function (event) {
            var message = event.data;
            if (message && message.type === "PREVIEW_UPDATE") {
                handlePreviewMessage(message.payload);
            }
        });

        window.addEventListener("online", function () {
            state.lastUpdated = null;
            fetchConfig();
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
