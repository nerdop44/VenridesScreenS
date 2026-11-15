/* eslint-disable */
// tv_preview.js - Previsualizador de TV en tiempo real para el panel de Odoo
// Se encarga de cargar la configuración de la empresa y enviarla al iframe embebido
// mediante postMessage, para que los cambios se vean inmediatamente en la TV.

odoo.define('vscreens.tv_preview', function (require) {
    "use strict";

    var core = require('web.core');
    var rpc = require('web.rpc');
    var session = require('web.session');
    var time = require('web.time');

    var _t = core._t;

    var TV_URL = 'https://vscreens-tv.inverpave.com';

    // Función para obtener el ID de la empresa desde la URL de Odoo
    function getCompanyIdFromUrl() {
        var hash = window.location.hash || '';
        var match = hash.match(/id=(\d+)/);
        if (match) {
            return parseInt(match[1], 10);
        }
        return null;
    }

    // Función para obtener la configuración de la empresa desde la API
    function fetchCompanyConfig(companyId) {
        return rpc.query({
            model: 'vscreens.company',
            method: 'preview_config',
            args: [companyId],
        }).then(function (config) {
            return config;
        }).catch(function (err) {
            console.error('Error al obtener configuración de TV:', err);
            return null;
        });
    }

    // Función para enviar la configuración al iframe mediante postMessage
    function sendConfigToIframe(iframe, config) {
        if (!iframe || !iframe.contentWindow) {
            console.warn('Iframe de TV no disponible');
            return;
        }
        try {
            iframe.contentWindow.postMessage({
                type: 'PREVIEW_UPDATE',
                payload: config,
            }, '*');
            console.log('VScreenS: Configuración enviada al iframe de TV');
        } catch (e) {
            console.error('Error al enviar postMessage al iframe:', e);
        }
    }

    // Función principal para inicializar el previsualizador
    function initTVPreview() {
        var iframe = document.getElementById('tv-preview-iframe');
        if (!iframe) {
            return; // No estamos en una vista de empresa con el iframe
        }

        var companyId = getCompanyIdFromUrl();
        if (!companyId) {
            console.warn('No se pudo obtener el ID de la empresa desde la URL');
            return;
        }

        // Actualizar el src del iframe con el ID de la empresa
        iframe.src = TV_URL + '/?preview=' + companyId + '&t=' + Date.now();

        // Cargar y enviar la configuración
        fetchCompanyConfig(companyId).then(function (config) {
            if (config) {
                sendConfigToIframe(iframe, config);
            }
        });

        // Re-enviar cada 30 segundos para mantener sincronizado
        setInterval(function () {
            fetchCompanyConfig(companyId).then(function (config) {
                if (config) {
                    sendConfigToIframe(iframe, config);
                }
            });
        }, 30000);

        // Re-enviar al recuperar el foco de la pestaña
        window.addEventListener('focus', function () {
            fetchCompanyConfig(companyId).then(function (config) {
                if (config) {
                    sendConfigToIframe(iframe, config);
                }
            });
        });
    }

    // Exponer función pública para sincronización manual desde el botón
    window.syncTvPreview = function () {
        var iframe = document.getElementById('tv-preview-iframe');
        var companyId = getCompanyIdFromUrl();
        if (!iframe || !companyId) {
            console.warn('No se puede sincronizar: iframe o companyId no disponibles');
            return;
        }
        fetchCompanyConfig(companyId).then(function (config) {
            if (config) {
                sendConfigToIframe(iframe, config);
                // Mostrar notificación breve
                var statusEl = document.getElementById('tv-sync-status');
                if (statusEl) {
                    statusEl.textContent = 'Sincronizado';
                    statusEl.style.color = '#10b981';
                    setTimeout(function () {
                        statusEl.textContent = 'Listo';
                        statusEl.style.color = '#666';
                    }, 2000);
                }
            }
        });
    };

    // Inicializar cuando el DOM esté listo
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initTVPreview);
    } else {
        initTVPreview();
    }
});
