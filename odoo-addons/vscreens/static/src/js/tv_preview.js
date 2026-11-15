/**
 * VScreenS — Previsualizador de TV embebido en Odoo
 *
 * Detecta cuando el usuario está en el formulario de vscreens.company,
 * configura un <iframe> con la URL de la TV y envía postMessage
 * (type: 'PREVIEW_UPDATE') con la configuración de la empresa para que
 * el administrador vea los cambios en tiempo real sin salir de Odoo.
 *
 * El postMessage se envía:
 * - Al cargar la página / el iframe
 * - Cada 30 segundos (captura guardados automáticos)
 * - Al recuperar el foco de la pestaña (vuelve a Odoo)
 * - Al hacer clic en el botón "Sincronizar TV" (expuesto como window.syncTvPreview)
 */

(function () {
    "use strict";

    const TV_URL = "https://vscreens-tv.inverpave.com";
    const POLL_INTERVAL = 30000; // 30 segundos

    /* ------------------------------------------------------------------ */
    /* Helpers                                                            */
    /* ------------------------------------------------------------------ */

    function getHashParam(name) {
        const hash = window.location.hash || "";
        const regex = new RegExp("[?&]" + name + "=([^&]*)");
        const match = hash.match(regex);
        return match ? decodeURIComponent(match[1]) : null;
    }

    function getCompanyId() {
        const id = getHashParam("id");
        return id ? parseInt(id, 10) : null;
    }

    function getModel() {
        return getHashParam("model");
    }

    function isVscreensCompanyForm() {
        return getModel() === "vscreens.company";
    }

    function sendPostMessage(iframe, config) {
        if (!iframe || !iframe.contentWindow) {
            return;
        }
        try {
            iframe.contentWindow.postMessage(
                {
                    type: "PREVIEW_UPDATE",
                    payload: config,
                },
                "*"
            );
            console.log(
                "[VScreenS TV Preview] PREVIEW_UPDATE enviado:",
                config && config.name ? config.name : config && config.id ? config.id : config
            );
        } catch (err) {
            console.error("[VScreenS TV Preview] Error enviando postMessage:", err);
        }
    }

    function fetchPreviewConfig(iframe, companyId) {
        if (!companyId) {
            return;
        }
        fetch("/companies/" + companyId + "/preview-config")
            .then(function (res) {
                if (!res.ok) {
                    throw new Error("HTTP " + res.status);
                }
                return res.json();
            })
            .then(function (config) {
                sendPostMessage(iframe, config);
            })
            .catch(function (err) {
                console.error("[VScreenS TV Preview] Error obteniendo config:", err);
                // Fallback: enviar al menos el ID para que la TV muestre algo
                sendPostMessage(iframe, { id: companyId, is_active: true });
            });
    }

    function setupIframe(companyId) {
        const iframe = document.getElementById("tv-preview-iframe");
        if (!iframe) {
            return;
        }

        const src = TV_URL + "/?preview=" + companyId + "&t=" + Date.now();
        if (iframe.src !== src && iframe.src.indexOf("about:blank") === -1) {
            // Evitar recargar innecesariamente si ya tiene el src correcto
            if (iframe.src.indexOf("preview=" + companyId) === -1) {
                iframe.src = src;
            }
        }

        iframe.onload = function () {
            fetchPreviewConfig(iframe, companyId);
        };

        // Si el iframe ya cargó previamente, enviar config inmediatamente
        if (iframe.contentWindow) {
            fetchPreviewConfig(iframe, companyId);
        }
    }

    function init() {
        if (!isVscreensCompanyForm()) {
            return;
        }

        const companyId = getCompanyId();
        if (!companyId) {
            return;
        }

        // Intento inmediato
        setupIframe(companyId);

        // Reintento tras corto retraso (Odoo renderiza la vista de forma asíncrona)
        setTimeout(function () {
            setupIframe(companyId);
        }, 1000);

        // Reenvío periódico para capturar guardados automáticos del formulario
        setInterval(function () {
            setupIframe(companyId);
        }, POLL_INTERVAL);

        // Reenvío al recuperar el foco de la pestaña (usuario vuelve a Odoo)
        window.addEventListener("focus", function () {
            setTimeout(function () {
                setupIframe(companyId);
            }, 500);
        });
    }

    /* ------------------------------------------------------------------ */
    /* API pública                                                        */
    /* ------------------------------------------------------------------ */

    /**
     * Fuerza un re-envío inmediato del postMessage al iframe embebido.
     * Puede llamarse desde un botón de la vista de Odoo.
     */
    window.syncTvPreview = function () {
        const companyId = getCompanyId();
        const iframe = document.getElementById("tv-preview-iframe");
        if (companyId && iframe) {
            fetchPreviewConfig(iframe, companyId);
        }
    };

    /* ------------------------------------------------------------------ */
    /* Botón de sincronizar (delegación de eventos, evita onclick inline) */
    /* ------------------------------------------------------------------ */

    document.addEventListener("click", function (event) {
        var btn = event.target.closest(".btn-sync-tv-preview");
        if (btn) {
            event.preventDefault();
            window.syncTvPreview();
        }
    });

    /* ------------------------------------------------------------------ */
    /* Inicialización                                                     */
    /* ------------------------------------------------------------------ */

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
