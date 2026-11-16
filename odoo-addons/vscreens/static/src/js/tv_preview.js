import { Component, onMounted, onWillStart, useEffect, useProps, useRef, useState } from "@odoo/owl";
import { registry } from "@web/core/registry";
import { useService } from "@web/core/utils/hooks";
import { standardFieldProps } from "@web/views/fields/standard_field_props";

const SIMPLE_FIELDS = [
    "name",
    "layout_type",
    "primary_color",
    "secondary_color",
    "accent_color",
    "logo_url",
    "video_source",
    "filler_keywords",
    "google_drive_link",
    "priority_content_url",
    "pause_duration",
    "ad_frequency",
    "sidebar_header_type",
    "sidebar_header_value",
];

/**
 * Panel de previsualización en vivo de la TV.
 *
 * Se coloca sobre las pestañas del formulario de empresa. Mientras el usuario
 * edita, los valores del formulario se envían al iframe (postMessage) para que
 * el cambio se vea al instante, sin guardar. El botón "Enviar" guarda y publica
 * la configuración en todas las pantallas o sólo en las seleccionadas.
 */
export class VscreensTvPreviewField extends Component {
    static template = "vscreens.TvPreviewField";
    props = useProps(standardFieldProps);

    setup() {
        this.orm = useService("orm");
        this.notification = useService("notification");
        this.iframe = useRef("iframe");
        this.companyId = this.props.record.resId;
        this.baseConfig = {};
        this.previewUrl = `https://vscreens-tv.inverpave.com/?preview=${this.companyId}`;

        this.state = useState({
            devices: [],
            selected: {},
            status: "Conectando…",
            statusClass: "vs_tv_status_wait",
            sending: false,
        });

        onWillStart(async () => {
            if (!this.companyId) {
                return;
            }
            this.baseConfig = await this.orm.call("vscreens.company", "preview_config", [
                [this.companyId],
            ]);
            this.state.devices = await this.orm.searchRead(
                "vscreens.device",
                [["company_id", "=", this.companyId]],
                ["name", "is_online", "is_active", "last_ping"],
                { order: "name" }
            );
        });

        onMounted(() => {
            this.sendPreview();
        });

        // Reenvía la vista previa cada vez que cambia cualquier campo visible.
        useEffect(
            () => {
                this.sendPreview();
            },
            () => [this.snapshot()]
        );
    }

    get iframeEl() {
        return this.iframe.el;
    }

    // ------------------------------------------------------------------
    // Construcción del borrador (lo que el usuario ve en pantalla)
    // ------------------------------------------------------------------
    rowData(name) {
        const value = this.props.record.data[name];
        if (!value) {
            return [];
        }
        const list = typeof value.toArray === "function" ? value.toArray() : Array.from(value);
        return list
            .map((item) => (item && item.data ? item.data : item))
            .filter((item) => item && !item.__remove);
    }

    snapshot() {
        try {
            return JSON.stringify(this.buildDraft());
        } catch (error) {
            return "";
        }
    }

    buildDraft() {
        const data = this.props.record.data;
        const draft = {};
        for (const field of SIMPLE_FIELDS) {
            if (data[field] !== undefined) {
                draft[field] = data[field];
            }
        }

        const playlist = this.rowData("playlist_items").filter(
            (row) => row.url && row.is_active !== false
        );
        if (playlist.length) {
            draft.video_playlist = playlist.map((row) => ({
                url: row.url,
                title: row.title || "",
            }));
        }

        const scheduled = this.rowData("scheduled_video_items").filter(
            (row) => row.url && row.start_datetime && row.is_active !== false
        );
        if (scheduled.length) {
            draft.scheduled_videos = scheduled.map((row) => ({
                url: row.url,
                title: row.title || "",
                start: row.start_datetime,
                end: row.end_datetime || false,
                duration: row.duration || 300,
                scheduled: true,
            }));
        }

        const sidebar = this.rowData("sidebar_items").filter(
            (row) => (row.value || row.label) && row.is_active !== false
        );
        if (sidebar.length) {
            draft.sidebar_content = sidebar.map((row) => ({
                type: "text",
                label: row.label || "",
                value: row.value || row.label || "",
                icon: row.icon || false,
                color: row.color || "#ffffff",
            }));
        }

        const bottom = this.rowData("bottom_bar_items").filter(
            (row) => (row.value || row.label) && row.is_active !== false
        );
        if (bottom.length) {
            draft.bottom_bar_content = {
                ...(this.baseConfig.bottom_bar_content || {}),
                messages: bottom.map((row) => row.value || row.label),
            };
        }

        const design = this.rowData("design_settings_id")[0];
        if (design) {
            draft.design_settings = {
                ...(this.baseConfig.design_settings || {}),
                name_font: design.title_font || "inherit",
                name_color: design.title_color || "#ffffff",
                name_size: design.title_size || "1.2rem",
                name_weight: design.title_weight || "bold",
                sidebar_width: design.sidebar_width || 22,
                sidebar_effect: design.sidebar_effect || "none",
                sidebar_bg: design.sidebar_bg || "#1e293b",
                sidebar_text: design.sidebar_text || "#ffffff",
                bottom_bar_bg: design.bottom_bar_bg || "#0a0e1a",
                bottom_bar_text: design.bottom_bar_text || "#ffffff",
                show_bcv: design.show_bcv !== false,
                bcv_color: design.bcv_color || "#10b981",
                bcv_font: design.bcv_font || "inherit",
            };
        }

        return draft;
    }

    // ------------------------------------------------------------------
    // Envío en vivo al iframe
    // ------------------------------------------------------------------
    async sendPreview() {
        if (!this.iframeEl || !this.iframeEl.contentWindow || !this.companyId) {
            return;
        }
        try {
            const config = await this.orm.call(
                "vscreens.company",
                "preview_config_draft",
                [this.companyId, this.buildDraft()]
            );
            this.iframeEl.contentWindow.postMessage(
                { type: "PREVIEW_UPDATE", payload: config },
                "*"
            );
            this.state.status = "Vista previa en vivo";
            this.state.statusClass = "vs_tv_status_live";
        } catch (error) {
            console.error("VScreenS: error al actualizar la vista previa", error);
            this.state.status = "Sin conexión con la TV";
            this.state.statusClass = "vs_tv_status_error";
        }
    }

    toggleDevice(deviceId) {
        this.state.selected[deviceId] = !this.state.selected[deviceId];
    }

    get selectedIds() {
        return Object.keys(this.state.selected)
            .filter((key) => this.state.selected[key])
            .map((key) => Number(key));
    }

    // ------------------------------------------------------------------
    // Publicar en las pantallas reales
    // ------------------------------------------------------------------
    async pushToDevices() {
        if (!this.companyId || this.state.sending) {
            return;
        }
        this.state.sending = true;
        try {
            await this.props.record.save();
            const ids = this.selectedIds;
            await this.orm.call(
                "vscreens.company",
                "action_push_config",
                [[this.companyId]],
                { device_ids: ids }
            );
            this.baseConfig = await this.orm.call("vscreens.company", "preview_config", [
                [this.companyId],
            ]);
            this.sendPreview();
            this.notification.add(
                ids.length
                    ? `Configuración enviada a ${ids.length} pantalla(s).`
                    : "Configuración enviada a todas las pantallas de la empresa.",
                { type: "success" }
            );
        } catch (error) {
            console.error("VScreenS: error al publicar la configuración", error);
            this.notification.add("No se pudo publicar la configuración.", {
                type: "danger",
            });
        } finally {
            this.state.sending = false;
        }
    }

    openFullscreen() {
        window.open(this.previewUrl, "_blank", "noopener");
    }
}

registry.category("fields").add("vscreens_tv_preview", {
    component: VscreensTvPreviewField,
    supportedTypes: ["integer"],
    displayName: "Vista previa en vivo de TV",
});
