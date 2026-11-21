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
    "address",
    "allow_youtube_control",
    "youtube_control_minutes",
    "odoo_link_enabled",
    "odoo_link_label",
    "odoo_link_icon",
    "odoo_link_color",
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
        this.logoStamp = Date.now();
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
            const tvBase = (this.baseConfig && this.baseConfig.tv_url) || "https://vscreens-tv.inverpave.com";
            const pt = (this.baseConfig && this.baseConfig.preview_token) || "";
            this.previewUrl = `${tvBase.replace(/\/$/, "")}/?preview=${this.companyId}${pt ? `&pt=${encodeURIComponent(pt)}` : ""}`;
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
                image_url: row.image_url || false,
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

        const logoImg = document.querySelector('.o_field_widget[name="logo"] img');
        if (logoImg && logoImg.src && logoImg.src.startsWith("data:")) {
            draft.logo_url = logoImg.src;
        } else if (data.logo) {
            draft.logo_url = `${window.location.origin}/web/image/vscreens.company/${this.companyId}/logo?unique=${this.logoStamp}`;
        }

        const design = this.rowData("design_settings_id")[0] || {};
        const pick = (dsKey, legacyKey, fallback) => {
            if (data[dsKey] !== undefined) return data[dsKey];
            if (design[legacyKey] !== undefined) return design[legacyKey];
            return fallback;
        };
        draft.design_settings = {
            ...(this.baseConfig.design_settings || {}),
            theme_preset: pick("ds_theme_preset", "theme_preset", "default") || "default",
            sidebar_bg_image: pick("ds_sidebar_bg_image", "sidebar_bg_image", "") || "",
            bottom_bar_bg_image: pick("ds_bottom_bar_bg_image", "bottom_bar_bg_image", "") || "",
            name_font: pick("ds_title_font", "title_font", "inherit") || "inherit",
            name_color: pick("ds_title_color", "title_color", "#ffffff") || "#ffffff",
            name_size: pick("ds_title_size", "title_size", "1.2rem") || "1.2rem",
            name_weight: pick("ds_title_weight", "title_weight", "bold") || "bold",
            sidebar_width: pick("ds_sidebar_width", "sidebar_width", 22) || 22,
            sidebar_effect: pick("ds_sidebar_effect", "sidebar_effect", "none") || "none",
            sidebar_bg: pick("ds_sidebar_bg", "sidebar_bg", "#1e293b") || "#1e293b",
            sidebar_text: pick("ds_sidebar_text", "sidebar_text", "#ffffff") || "#ffffff",
            sidebar_animation: pick("ds_sidebar_animation", "sidebar_animation", "slide_up") || "slide_up",
            sidebar_font_scale: pick("ds_sidebar_font_scale", "sidebar_font_scale", "normal") || "normal",
            side_subtitle: pick("ds_side_subtitle", "side_subtitle", "") || "",
            show_side_footer: pick("ds_show_side_footer", "show_side_footer", true) !== false,
            side_footer_text: pick("ds_side_footer_text", "side_footer_text", "") || "",
            side_footer_animation: pick("ds_side_footer_animation", "side_footer_animation", "marquee") || "marquee",
            show_card_frame: pick("ds_show_card_frame", "show_card_frame", true) !== false,
            show_slide_counter: pick("ds_show_slide_counter", "show_slide_counter", false) === true,
            show_side_menu: pick("ds_show_side_menu", "show_side_menu", true) !== false,
            side_menu_animation: pick("ds_side_menu_animation", "side_menu_animation", "rotate") || "rotate",
            safety_margin: Number(pick("ds_safety_margin", "safety_margin", 2) ?? 2),
            show_side_clock: pick("ds_show_side_clock", "show_side_clock", false) === true,
            bottom_bar_bg: pick("ds_bottom_bar_bg", "bottom_bar_bg", "#0a0e1a") || "#0a0e1a",
            bottom_bar_text: pick("ds_bottom_bar_text", "bottom_bar_text", "#ffffff") || "#ffffff",
            bottom_bar_height: Number(pick("ds_bottom_bar_height", "bottom_bar_height", 10) || 10),
            bottom_bar_border: pick("ds_bottom_bar_border", "bottom_bar_border", true) !== false,
            ticker_speed: Number(pick("ds_ticker_speed", "ticker_speed", 30) || 30),
            ticker_color: pick("ds_ticker_color", "ticker_color", "#ffffff") || "#ffffff",
            ticker_font: pick("ds_ticker_font", "ticker_font", "inherit") || "inherit",
            show_bottom_clock: pick("ds_show_bottom_clock", "show_bottom_clock", true) !== false,
            show_topbar_date: pick("ds_show_topbar_date", "show_topbar_date", true) !== false,
            show_live_badge: pick("ds_show_live_badge", "show_live_badge", true) !== false,
            show_social_in_ticker: pick("ds_show_social_in_ticker", "show_social_in_ticker", true) !== false,
            show_bcv: pick("ds_show_bcv", "show_bcv", true) !== false,
            bcv_color: pick("ds_bcv_color", "bcv_color", "#10b981") || "#10b981",
            bcv_font: pick("ds_bcv_font", "bcv_font", "inherit") || "inherit",
        };

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

    async toggleExpanded() {
        const expanding = !this._expanded();
        this._expanded.set(expanding);
        const panel = document.querySelector(".vs_tv_preview");
        if (!panel) {
            return;
        }
        try {
            if (expanding && panel.requestFullscreen) {
                await panel.requestFullscreen();
            } else if (!expanding && document.fullscreenElement) {
                await document.exitFullscreen();
            }
        } catch (error) {
            console.warn("VScreenS: no se pudo activar pantalla completa", error);
        }
    }

    async openFullscreen() {
        try {
            await this.props.record.save();
        } catch (error) {
            return;
        }
        window.open(this.previewUrl, "_blank", "noopener");
    }
}

registry.category("fields").add("vscreens_tv_preview", {
    component: VscreensTvPreviewField,
    supportedTypes: ["integer"],
    displayName: "Vista previa en vivo de TV",
});
