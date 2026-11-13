/** Widget de Benry para el website VScreenS */
(function () {
    "use strict";

    function initBenry() {
        if (document.getElementById("benry-widget")) return;

        var widget = document.createElement("div");
        widget.id = "benry-widget";
        widget.innerHTML =
            '<div id="benry-panel" style="display:none; position:fixed; bottom:100px; right:20px; width:360px; max-width:92vw; height:470px; background:#0d0d1a; border:1px solid #333; border-radius:15px; padding:15px; z-index:99999; box-shadow:0 10px 40px rgba(0,0,0,0.5);">' +
                '<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">' +
                    '<h5 style="color:#c8ff00; margin:0; font-weight:800;">Benry AI</h5>' +
                    '<button id="benry-close" style="background:none; border:none; color:#fff; font-size:22px; cursor:pointer;">&times;</button>' +
                '</div>' +
                '<div id="benry-messages" style="height:350px; overflow-y:auto; color:#e0e0e0; font-size:14px; padding:10px; background:#1a1a2e; border-radius:10px;"></div>' +
                '<div style="display:flex; margin-top:10px;">' +
                    '<input id="benry-input" type="text" placeholder="Escribe un mensaje..." style="flex:1; padding:10px; border-radius:8px 0 0 8px; border:1px solid #333; background:#1a1a2e; color:#fff; min-width:0;"/>' +
                    '<button id="benry-send" style="padding:10px 15px; background:#c8ff00; color:#000; border:none; border-radius:0 8px 8px 0; font-weight:bold; cursor:pointer;">Enviar</button>' +
                '</div>' +
            '</div>' +
            '<button id="benry-toggle" aria-label="Abrir chat Benry" style="position:fixed; bottom:20px; right:20px; width:62px; height:62px; border-radius:50%; background:#c8ff00; border:none; font-size:28px; cursor:pointer; z-index:99999; box-shadow:0 4px 15px rgba(0,0,0,0.3);">&#129302;</button>';

        document.body.appendChild(widget);

        var sessionId = "web-" + Date.now() + "-" + Math.random().toString(36).slice(2, 8);
        var messages = document.getElementById("benry-messages");
        var panel = document.getElementById("benry-panel");

        document.getElementById("benry-toggle").onclick = function () {
            panel.style.display = panel.style.display === "none" ? "block" : "none";
        };
        document.getElementById("benry-close").onclick = function () {
            panel.style.display = "none";
        };

        function addMsg(text, isUser) {
            var div = document.createElement("div");
            div.style.margin = "8px 0";
            div.style.padding = "8px 12px";
            div.style.borderRadius = "10px";
            div.style.maxWidth = "85%";
            div.style.marginLeft = isUser ? "auto" : "0";
            div.style.background = isUser ? "#c8ff00" : "#2d3748";
            div.style.color = isUser ? "#000" : "#fff";
            div.style.whiteSpace = "pre-wrap";
            div.textContent = text;
            messages.appendChild(div);
            messages.scrollTop = messages.scrollHeight;
        }

        function send() {
            var input = document.getElementById("benry-input");
            var text = input.value.trim();
            if (!text) return;
            addMsg(text, true);
            input.value = "";
            fetch("/api/benry/chat", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ message: text, session_id: sessionId }),
            })
                .then(function (r) { return r.json(); })
                .then(function (data) {
                    addMsg(data.response || "Sin respuesta", false);
                })
                .catch(function () {
                    addMsg("Error de conexion. Intenta de nuevo.", false);
                });
        }

        document.getElementById("benry-send").onclick = send;
        document.getElementById("benry-input").onkeypress = function (e) {
            if (e.key === "Enter") send();
        };

        addMsg("Hola! Soy Benry, tu asistente de VScreenS. En que puedo ayudarte?", false);
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", initBenry);
    } else {
        initBenry();
    }
})();
