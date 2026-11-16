import {
    Component,
    onMounted,
    onWillStart,
    signal,
    useOnChange,
    useProps,
} from "@odoo/owl";
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
    "phone",
    "whatsapp",
    "instagram",
    "facebook",
    "tiktok",
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

    iframeRef = signal.ref();

    setup() {
        this.orm = useService("orm");
        this.notification = useService("notification");
        this.companyId = this.props.record.resId;
        this.baseConfig = {};
        this.previewUrl = `https://vscreens-tv.inverpave.com/?preview=${this.companyId}`;

        this._devices = signal([]);
        this._selected = signal({});
        this._status = signal("Conectando…");
        this._statusClass = signal("vs_tv_status_wait");
        this._sending = signal(false);
        this._expanded = signal(false);

        onWillStart(async () => {
            if (!this.companyId) {
                return;
            }
            this.baseConfig = await this.orm.call("vscreens.company", "preview_config", [
                [this.companyId],
            ]);
            this._devices.set(
                await this.orm.searchRead(
                    "vscreens.device",
                    [["company_id", "=", this.companyId]],
                    ["name", "is_online", "is_active", "last_ping"],
                    { order: "name" }
                )
            );
        });

        onMounted(() => {
            this.sendPreview();
        });

        // Reenvía la vista previa cada vez que cambia cualquier campo visible.
        useOnChange(
            () => [this.snapshot()],
            () => this.sendPreview(),
            { initialRun: false }
        );
    }

    get devices() {
        return this._devices();
    }

    get selected() {
        return this._selected();
    }

    get status() {
        return this._status();
    }

    get statusClass() {
        return this._statusClass();
    }

    get sending() {
        return this._sending();
    }

    get expanded() {
        return this._expanded();
    }

    get onlineDevices() {
        return this._devices().filter((device) => device.is_online && device.is_active).length;
    }

    get inactiveItems() {
        const countInactive = (name) =>
            this.rowData(name).filter((row) => row.is_active === false).length;
        return (
            countInactive("playlist_items") +
            countInactive("sidebar_items") +
            countInactive("bottom_bar_items") +
            countInactive("scheduled_video_items")
        );
    }

    get iframeEl() {
        return this.iframeRef();
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
            draft.video_playlist = playlist.map((row) => row.url);
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
        const socials = {};
        if (data.whatsapp) {
            socials.whatsapp = data.whatsapp;
        }
        if (data.instagram) {
            socials.instagram = String(data.instagram).replace(/^@/, "");
        }
        if (data.phone) {
            socials.phone = data.phone;
        }
        if (bottom.length || Object.keys(socials).length) {
            draft.bottom_bar_content = {
                ...(this.baseConfig.bottom_bar_content || {}),
                ...(bottom.length ? { messages: bottom.map((row) => row.value || row.label) } : {}),
                ...socials,
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
        const iframe = this.iframeEl;
        if (!iframe || !iframe.contentWindow || !this.companyId) {
            return;
        }
        try {
            const config = await this.orm.call(
                "vscreens.company",
                "preview_config_draft",
                [this.companyId, this.buildDraft()]
            );
            iframe.contentWindow.postMessage(
                { type: "PREVIEW_UPDATE", payload: config },
                "*"
            );
            this._status.set("Vista previa en vivo");
            this._statusClass.set("vs_tv_status_live");
        } catch (error) {
            console.error("VScreenS: error al actualizar la vista previa", error);
            this._status.set("Sin conexión con la TV");
            this._statusClass.set("vs_tv_status_error");
        }
    }

    toggleDevice(deviceId) {
        this._selected.set({
            ...this._selected(),
            [deviceId]: !this._selected()[deviceId],
        });
    }

    get selectedIds() {
        const selected = this._selected();
        return Object.keys(selected)
            .filter((key) => selected[key])
            .map((key) => Number(key));
    }

    // ------------------------------------------------------------------
    // Publicar en las pantallas reales
    // ------------------------------------------------------------------
    async pushToDevices() {
        if (!this.companyId || this._sending()) {
            return;
        }
        this._sending.set(true);
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
            const online = this.onlineDevices;
            this.notification.add(
                ids.length
                    ? `Configuración enviada a ${ids.length} pantalla(s).`
                    : "Configuración enviada a todas las pantallas de la empresa.",
                { type: "success" }
            );
            if (!online) {
                this.notification.add(
                    "Ninguna pantalla está conectada en este momento; aplicarán los cambios al reconectarse.",
                    { type: "warning" }
                );
            }
        } catch (error) {
            console.error("VScreenS: error al publicar la configuración", error);
            this.notification.add("No se pudo publicar la configuración.", {
                type: "danger",
            });
        } finally {
            this._sending.set(false);
        }
    }

    toggleExpanded() {
        this._expanded.set(!this._expanded());
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
