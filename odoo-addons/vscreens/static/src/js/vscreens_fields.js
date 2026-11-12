import { Component, useProps, useState } from "@odoo/owl";
import { registry } from "@web/core/registry";
import { standardFieldProps } from "@web/views/fields/standard_field_props";

class VscreensSidebarField extends Component {
    static template = "vscreens.SidebarField";
    props = useProps(standardFieldProps);

    setup() {
        const value = this.props.record.data[this.props.name];
        this.state = useState({
            items: Array.isArray(value) ? value : [],
        });
    }

    commit() {
        this.props.record.update({ [this.props.name]: this.state.items });
    }

    addText() {
        this.state.items = [...this.state.items, { type: "text", value: "", duration: 10, font_size: "1.4rem", weight: "bold" }];
        this.commit();
    }

    addImage() {
        this.state.items = [...this.state.items, { type: "image", value: "", duration: 10 }];
        this.commit();
    }

    removeItem(index) {
        this.state.items = this.state.items.filter((_, i) => i !== index);
        this.commit();
    }
}

class VscreensBottomBarField extends Component {
    static template = "vscreens.BottomBarField";
    props = useProps(standardFieldProps);

    setup() {
        const value = this.props.record.data[this.props.name];
        const data = value && typeof value === "object" && !Array.isArray(value) ? value : {};
        this.state = useState({
            data: {
                static: data.static || "",
                whatsapp: data.whatsapp || "",
                instagram: data.instagram || "",
                messages: Array.isArray(data.messages) ? data.messages : [],
                font_size: data.font_size || "1rem",
                color: data.color || "#ffffff",
                weight: data.weight || "normal",
            },
        });
    }

    commit() {
        this.props.record.update({ [this.props.name]: this.state.data });
    }

    addMessage() {
        this.state.data.messages = [...this.state.data.messages, ""];
        this.commit();
    }

    setMessage(index, value) {
        this.state.data.messages[index] = value;
        this.commit();
    }

    removeMessage(index) {
        this.state.data.messages = this.state.data.messages.filter((_, i) => i !== index);
        this.commit();
    }
}

class VscreensVideosField extends Component {
    static template = "vscreens.VideosField";
    props = useProps(standardFieldProps);

    setup() {
        const value = this.props.record.data[this.props.name];
        this.state = useState({
            items: Array.isArray(value) ? value : [],
        });
    }

    commit() {
        this.props.record.update({ [this.props.name]: this.state.items });
    }

    addVideo() {
        this.state.items = [...this.state.items, ""];
        this.commit();
    }

    setVideo(index, value) {
        this.state.items[index] = value;
        this.commit();
    }

    removeVideo(index) {
        this.state.items = this.state.items.filter((_, i) => i !== index);
        this.commit();
    }
}

class VscreensDesignField extends Component {
    static template = "vscreens.DesignField";
    props = useProps(standardFieldProps);

    setup() {
        const value = this.props.record.data[this.props.name];
        const data = value && typeof value === "object" && !Array.isArray(value) ? value : {};
        this.state = useState({
            data: {
                primary_color: data.primary_color || "#1a202c",
                secondary_color: data.secondary_color || "#2d3748",
                accent_color: data.accent_color || "#4a5568",
                sidebar_bg: data.sidebar_bg || "#111827",
                sidebar_text: data.sidebar_text || "#ffffff",
                bottom_bar_bg: data.bottom_bar_bg || "#000000",
                bottom_bar_text: data.bottom_bar_text || "#ffffff",
                sidebar_width: data.sidebar_width || 22,
                bottom_bar_height: data.bottom_bar_height || 10,
                show_bcv: data.show_bcv !== false,
                sidebar_effect: data.sidebar_effect || "none",
                ticker_speed: data.ticker_speed || 30,
            },
        });
    }

    commit() {
        this.props.record.update({ [this.props.name]: this.state.data });
    }
}

registry.category("fields").add("vscreens_sidebar", {
    component: VscreensSidebarField,
    supportedTypes: ["json"],
    displayName: "Editor de barra lateral",
});

registry.category("fields").add("vscreens_bottombar", {
    component: VscreensBottomBarField,
    supportedTypes: ["json"],
    displayName: "Editor de barra inferior",
});

registry.category("fields").add("vscreens_videos", {
    component: VscreensVideosField,
    supportedTypes: ["json"],
    displayName: "Editor de videos",
});

registry.category("fields").add("vscreens_design", {
    component: VscreensDesignField,
    supportedTypes: ["json"],
    displayName: "Editor de diseño",
});
