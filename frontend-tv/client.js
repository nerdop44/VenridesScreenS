const API_URL = "https://apitv.venrides.com";
const CLIENT_ID_STORAGE_KEY = "device_uuid";

const urlParams = new URLSearchParams(window.location.search);
const previewCompanyId = urlParams.get('preview');

// Generate or Retrieve Device UUID
// Simple UUID Generator for compatibility with old Smart TV browsers
function generateUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
        var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}

// Generate or Retrieve Device UUID
let deviceUuid = localStorage.getItem(CLIENT_ID_STORAGE_KEY);
if (!deviceUuid) {
    // Try crypto if available, else fallback
    if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
        deviceUuid = crypto.randomUUID();
    } else {
        deviceUuid = generateUUID();
    }
    localStorage.setItem(CLIENT_ID_STORAGE_KEY, deviceUuid);
}

let player;
let currentKeywords = "";
let sidebarItems = [];
let bottomData = {};
let bcvRate = 0;
let rotationInterval;
let currentDriveLink = "";
let activePriorityUrl = "";
let isInterrupted = false;
let playerReady = false;
let playlist = [];
let currentVideoIndex = 0;
let lastPlaylistStr = "";
let lastAlertId = null;
let isAlertShowing = false;

// Load YouTube API
const tag = document.createElement('script');
tag.src = "https://www.youtube.com/iframe_api";
const firstScriptTag = document.getElementsByTagName('script')[0];
firstScriptTag.parentNode.insertBefore(tag, firstScriptTag);

function onYouTubeIframeAPIReady() {
    player = new YT.Player('main-video-player', {
        height: '100%',
        width: '100%',
        videoId: '5qap5aO4i9A',
        playerVars: {
            'autoplay': 1,
            'controls': 0,
            'mute': 0,
            'loop': 1,
            'playlist': '5qap5aO4i9A',
            'rel': 0,
            'showinfo': 0,
            'modestbranding': 1
        },
        events: {
            'onReady': onPlayerReady,
            'onStateChange': onPlayerStateChange
        }
    });
}

function onPlayerReady(event) {
    playerReady = true;
    event.target.unMute();
    event.target.setVolume(100);
    event.target.playVideo();
    console.log("YouTube Player Ready event fired.");
    setInterval(fetchConfig, 30000);
}

function loadNextVideo(source) {
    if (!source) return;
    let videoId = extractYoutubeId(source);
    if (!videoId) {
        // Keyword mapping logic
        const lowerK = source.toLowerCase();
        if (lowerK.includes('coffee') || lowerK.includes('jazz')) videoId = 'CH50zuS8dd0';
        else if (lowerK.includes('food') || lowerK.includes('restaurant')) videoId = 'J1vL0yW9f70';
        else if (lowerK.includes('city') || lowerK.includes('travel')) videoId = 'JB0A8Me8EKk';
        else if (lowerK.includes('beach') || lowerK.includes('ocean')) videoId = 'n61ULEU7CO0';
        else videoId = '5qap5aO4i9A';
    }

    if (playerReady && player && typeof player.loadVideoById === 'function') {
        console.log("YouTube Player Loading:", videoId, "Source:", source);
        player.loadVideoById({ videoId: videoId, suggestedQuality: 'hd1080' });
        return true;
    }
    return false;
}

function onPlayerStateChange(event) {
    if (event.data === YT.PlayerState.ENDED) {
        // If we are showing priority, loop it
        if (activePriorityUrl && (activePriorityUrl.includes('youtube.com') || activePriorityUrl.includes('youtu.be'))) {
            player.playVideo();
            return;
        }

        if (playlist.length > 1) {
            currentVideoIndex = (currentVideoIndex + 1) % playlist.length;
            loadNextVideo(playlist[currentVideoIndex]);
        } else {
            player.playVideo(); // Loop single video
        }
    }
}

// Setup Priority Video
document.addEventListener('DOMContentLoaded', () => {
    const priorityVideo = document.getElementById("priority-video");
    const priorityContainer = document.getElementById("priority-player-container");

    priorityVideo.onended = () => {
        priorityContainer.classList.add("hidden");
        priorityVideo.pause();
        isInterrupted = false;
        console.log("Priority video ended, resuming normal loop.");
    };

    // Initialize config fetch immediately
    fetchConfig();
});

// Helper to transform Drive URLs for Images (View)
function transformDriveImgUrl(url) {
    if (!url) return "";
    try {
        if (url.includes("drive.google.com") || url.includes("docs.google.com")) {
            // Match ID more permissively: /d/ID, id=ID, or just the ID string if sufficiently long
            const idMatch = url.match(/(?:\/d\/|id=|open\?id=)([-\w]{15,})/) || url.match(/([-\w]{25,})/);
            if (idMatch && idMatch[1]) {
                const id = idMatch[1];
                // Use lh3.googleusercontent.com for images as it handles CORS better and no 302 redirects
                return `https://lh3.googleusercontent.com/d/${id}=w1000?authuser=0`;
            }
        }
    } catch (e) { console.error("URL transform error", e); }
    return url;
}

// Helper to transform Drive URLs for Videos (Download/Stream)
function transformDriveVideoUrl(url) {
    if (!url) return "";
    try {
        if (url.includes("drive.google.com") || url.includes("docs.google.com")) {
            const idMatch = url.match(/(?:\/d\/|id=|open\?id=)([-\w]{15,})/) || url.match(/([-\w]{25,})/);
            if (idMatch && idMatch[1]) {
                return `https://drive.google.com/uc?export=download&id=${idMatch[1]}`;
            }
        }
    } catch (e) { console.error("URL transform error", e); }
    return url;
}

function handlePriorityContent(url) {
    if (!url || url === activePriorityUrl) {
        if (!url && activePriorityUrl) {
            // Priority removed, hide and resume
            const priorityContainer = document.getElementById("priority-player-container");
            if (priorityContainer) priorityContainer.classList.add("hidden");
            activePriorityUrl = null;
            isInterrupted = false;
        }
        return;
    }

    // Check if it's a YouTube URL
    const isYoutube = url.includes('youtube.com') || url.includes('youtu.be');

    if (isYoutube) {
        console.log("Priority content is YouTube, will be handled by main player logic.");
        activePriorityUrl = url;
        isInterrupted = false; // We use main player, so not "interrupted" by overlay
        const priorityContainer = document.getElementById("priority-player-container");
        if (priorityContainer) priorityContainer.classList.add("hidden");
        return;
    }

    activePriorityUrl = url;
    const priorityVideo = document.getElementById("priority-video");
    const priorityContainer = document.getElementById("priority-player-container");

    console.log("Triggering priority interruption (Direct Video):", url);
    priorityVideo.src = transformDriveVideoUrl(url);
    priorityContainer.classList.remove("hidden");
    priorityVideo.play().catch(e => console.error("Priority play error:", e));
    isInterrupted = true;
}

// Global Error Handler for debugging on TV
window.onerror = function (msg, url, lineNo, columnNo, error) {
    const nameEl = document.getElementById("company-name");
    if (nameEl) {
        nameEl.style.color = "#ff8e8e";
        nameEl.innerText = "Error: " + msg;
    }
    // Also show on registration screen if possible
    const uuidDisplay = document.getElementById("device-uuid-display");
    if (uuidDisplay) uuidDisplay.innerHTML += `<div style="color:red; font-size:0.6em; margin-top:20px;">[DEBUG] ${msg}</div>`;
    return false;
};

async function fetchConfig() {
    try {
        console.log("Fetching config for UUID:", deviceUuid);
        let url = `${API_URL}/devices/${deviceUuid}/config`;

        if (previewCompanyId) {
            console.log("Preview Mode active for Company ID:", previewCompanyId);
            url = `${API_URL}/companies/${previewCompanyId}/preview-config`;
        }

        const res = await fetch(url);

        if (res.status === 404) {
            console.log("Device not registered (404). Showing registration screen.");
            if (!previewCompanyId) showRegistrationScreen();
            return;
        }

        if (!res.ok) {
            throw new Error(`HTTP Error ${res.status}`);
        }

        const data = await res.json();
        window.currentConfig = data;
        console.log("Config received:", data);
        applyBranding(data);
    } catch (e) {
        console.error("Fetch Config Error:", e);

        // Show visibility on why it failed
        const nameEl = document.getElementById("company-name");
        if (nameEl) {
            nameEl.innerHTML = `Sin Conexión <br/><span style="font-size:0.5em; opacity:0.7;">${e.message}</span>`;
        }

        // Even if offline, show registration screen so they can see the UUID
        if (!window.currentConfig && !previewCompanyId) {
            showRegistrationScreen();
            const uuidDisplay = document.getElementById("device-uuid-display");
            if (uuidDisplay) {
                uuidDisplay.innerHTML = `${deviceUuid}<br/><span style="font-size:0.5em; color:#f87171;">Buscando servidor...</span>`;
            }
        }

        setTimeout(fetchConfig, 10000); // Retry in 10s
    }
}

function getContrastColor(hex) {
    if (!hex) return '#ffffff';
    const r = parseInt(hex.substring(1, 3), 16);
    const g = parseInt(hex.substring(3, 5), 16);
    const b = parseInt(hex.substring(5, 7), 16);
    return ((r * 299) + (g * 587) + (b * 114)) / 1000 >= 128 ? '#000000' : '#ffffff';
}

function applyBranding(data) {
    handlePriorityContent(data.priority_content_url);
    handleAlert(data.active_alert);
    handlePing(data.ping_command, data.name);
    const regOverlay = document.getElementById("registration-overlay");
    if (regOverlay) regOverlay.classList.add("hidden");
    const root = document.documentElement;
    const body = document.body;

    if (!data.is_active) {
        showSuspended();
        return;
    } else {
        document.getElementById("kill-switch").classList.add("hidden");
    }

    // Apply Layout & Colors
    body.className = data.layout_type || 'layout-a';
    const ds = data.design_settings || {};
    root.style.setProperty('--primary-color', data.primary_color || '#3e2723');
    root.style.setProperty('--secondary-color', data.secondary_color || '#5d4037');
    root.style.setProperty('--accent-color', data.accent_color || '#8d6e63');
    root.style.setProperty('--text-color', getContrastColor(data.primary_color));

    // Independent Bar Colors
    root.style.setProperty('--sidebar-bg', ds.sidebar_bg || data.primary_color || '#3e2723');
    root.style.setProperty('--sidebar-text', ds.sidebar_text || getContrastColor(data.primary_color));
    root.style.setProperty('--bottom-bg', ds.bottom_bar_bg || data.accent_color || '#8d6e63');
    root.style.setProperty('--ticker-text-color', ds.bottom_bar_text || getContrastColor(data.accent_color));

    // Sidebar Background Image & Effects
    const sidebar = document.getElementById("sidebar");
    if (sidebar) {
        // Apply background image
        if (ds.sidebar_bg_image) {
            const bgUrl = transformDriveImgUrl(ds.sidebar_bg_image);
            sidebar.style.backgroundImage = `url('${bgUrl}')`;
            sidebar.style.backgroundSize = "cover";
            sidebar.style.backgroundPosition = "center";
            sidebar.style.backgroundRepeat = "no-repeat";
        } else {
            sidebar.style.backgroundImage = "none";
        }

        // Apply visual effects
        const effect = ds.sidebar_effect || 'none';
        sidebar.classList.remove('effect-glass-3d', 'effect-neon-glow', 'effect-deep-shadow');

        if (effect === 'glass_3d') {
            sidebar.classList.add('effect-glass-3d');
        } else if (effect === 'neon_glow') {
            sidebar.classList.add('effect-neon-glow');
        } else if (effect === 'deep_shadow') {
            sidebar.classList.add('effect-deep-shadow');
        }
    }

    // Dynamic Animation Speed
    const tickerSpeed = ds.ticker_speed || 30;
    const tickerWrapper = document.getElementById("ticker-wrapper");
    if (tickerWrapper) {
        tickerWrapper.style.animationDuration = `${tickerSpeed}s`;
    }

    // Apply Content
    const nameEl = document.getElementById("company-name");
    nameEl.innerText = data.name;
    if (data.design_settings) {
        // ds already defined above
        nameEl.style.fontFamily = ds.name_font || 'inherit';
        nameEl.style.fontSize = ds.name_size || '1.2rem';
        nameEl.style.color = ds.name_color || 'inherit';
        nameEl.style.fontWeight = ds.name_weight || 'bold';
    }

    // Logo Handling (Bottom Logo)
    const logoImg = document.getElementById("logo");
    const logoContainer = document.getElementById("logo-container");
    // const ds = data.design_settings || {}; // Already defined

    // Determine which logo to show
    // Priority: sidebar_bottom_logo -> logo_url
    // Explicitly check sidebar_bottom_logo first as it corresponds to the new "Logo Inferior" section
    let logoUrl = ds.sidebar_bottom_logo;
    if (!logoUrl) logoUrl = data.logo_url;

    // Visibility Check
    // If show_bottom_logo is explicitly false, hide it. Default true.
    if (logoUrl && ds.show_bottom_logo !== false) {
        if (logoUrl.startsWith("/logos/")) logoUrl = "/api" + logoUrl;

        logoImg.src = transformDriveImgUrl(logoUrl);

        logoImg.style.transition = "width 0.3s ease, height 0.3s ease";

        // Size Control
        // Use new sidebar_bottom_logo_size if available, else legacy logo_size or default
        const size = ds.sidebar_bottom_logo_size || ds.logo_size || 85;

        logoImg.style.width = `${size}%`;
        logoImg.style.height = "auto";
        logoImg.style.maxWidth = "100%";
        logoImg.style.maxHeight = "100%";
        logoImg.style.objectFit = "contain";

        if (logoContainer) {
            const isLayoutB = document.body.classList.contains('layout-b');
            logoContainer.style.height = isLayoutB ? "12vh" : "18vh";
            logoContainer.style.display = "flex";
            logoContainer.style.justifyContent = "center";
            logoContainer.style.alignItems = "center";
            logoContainer.style.overflow = "hidden";
        }
        logoImg.classList.remove("hidden");
    } else {
        logoImg.classList.add("hidden");
        if (logoContainer) logoContainer.style.height = "0";
    }

    // Sidebar & Bottom Bar Data
    try {
        sidebarItems = Array.isArray(data.sidebar_content) ? data.sidebar_content : JSON.parse(data.sidebar_content || '[]');
    } catch (e) { console.error("Sidebar parse error", e); sidebarItems = []; }

    try {
        bottomData = (data.bottom_bar_content && typeof data.bottom_bar_content === 'object') ? data.bottom_bar_content : JSON.parse(data.bottom_bar_content || '{}');
    } catch (e) { console.error("Bottom bar parse error", e); bottomData = {}; }

    bcvRate = data.bcv_rate || 0;

    startSidebarRotation();
    updateBottomBar();

    // 4. Ad Frequency Logic (Priority Drive Video)
    handleAdFrequency(data);

    // Video Source Handling
    const playerDiv = document.getElementById("main-video-player");
    const drivePlayer = document.getElementById("drive-player");
    const youtubePriority = (data.priority_content_url && (data.priority_content_url.includes('youtube.com') || data.priority_content_url.includes('youtu.be'))) ? data.priority_content_url : null;
    const isDriveMode = data.video_source === 'drive' || data.video_source === 'direct';
    const showYoutube = youtubePriority || (!isDriveMode);

    if (showYoutube) {
        if (!isInterrupted) {
            drivePlayer.classList.add("hidden");
            playerDiv.classList.remove("hidden");
        }
        if (typeof drivePlayer.pause === 'function') drivePlayer.pause();

        // 1. Check for PRIORITY YOUTUBE
        if (youtubePriority) {
            if (youtubePriority !== lastPlaylistStr) {
                console.log("Priority YouTube detected:", youtubePriority);
                if (loadNextVideo(youtubePriority)) {
                    lastPlaylistStr = youtubePriority;
                    playlist = [youtubePriority]; // Treat as single playlist
                }
            }
            return;
        }

        // 2. Normal Playlist Handling
        let newPlaylist = [];
        if (data.video_playlist && Array.isArray(data.video_playlist) && data.video_playlist.length > 0) {
            newPlaylist = data.video_playlist;
        } else if (data.filler_keywords) {
            newPlaylist = [data.filler_keywords];
        } else {
            newPlaylist = ["nature"];
        }

        // Check if playlist changed
        const newPlStr = JSON.stringify(newPlaylist);
        if (newPlStr !== lastPlaylistStr) {
            console.log("Playlist updated:", newPlaylist);
            playlist = newPlaylist;
            lastPlaylistStr = newPlStr;
            currentVideoIndex = 0;

            if (!loadNextVideo(playlist[0])) {
                console.warn("YouTube player NOT ready yet. Update queued.");
                lastPlaylistStr = "";
            }
        }
    } else {
        if (!isInterrupted) {
            playerDiv.classList.add("hidden");
            drivePlayer.classList.remove("hidden");
        }

        if (data.google_drive_link && data.google_drive_link !== currentDriveLink) {
            currentDriveLink = data.google_drive_link;
            const finalUrl = data.video_source === 'drive' ? transformDriveVideoUrl(data.google_drive_link) : data.google_drive_link;
            console.log("Loading Background Video:", finalUrl);
            drivePlayer.src = finalUrl;
            drivePlayer.play().catch(e => console.log("Autoplay blocked:", e));
        }
    }
}

let adInterval;
function handleAdFrequency(data) {
    if (!data.ad_frequency || data.ad_frequency <= 0 || !data.google_drive_link) {
        if (adInterval) clearInterval(adInterval);
        return;
    }

    const freqMs = data.ad_frequency * 1000;
    if (adInterval) clearInterval(adInterval);

    adInterval = setInterval(() => {
        if (isInterrupted || isAlertShowing) return;
        playPriorityAd(data);
    }, freqMs);
}

function playPriorityAd(data) {
    const priorityContainer = document.getElementById("priority-player-container");
    const priorityVideo = document.getElementById("priority-video");
    if (!priorityContainer || !priorityVideo) return;

    console.log("Starting Priority Ad...");
    isInterrupted = true;

    // Pause main player
    if (player && typeof player.pauseVideo === 'function') player.pauseVideo();
    const drivePlayer = document.getElementById("drive-player");
    if (drivePlayer && typeof drivePlayer.pause === 'function') drivePlayer.pause();

    // Setup Priority Ad
    const finalUrl = data.video_source === 'drive' ? transformDriveVideoUrl(data.google_drive_link) : data.google_drive_link;
    priorityVideo.src = finalUrl;
    priorityContainer.classList.remove("hidden");

    priorityVideo.play().catch(e => console.log("Ad Autoplay blocked:", e));

    // Wait for end or pause_duration
    const pauseMs = (data.pause_duration || 1) * 60 * 1000;

    const endAd = () => {
        priorityContainer.classList.add("hidden");
        priorityVideo.pause();
        isInterrupted = false;

        // Resume main player
        if (player && typeof player.playVideo === 'function') player.playVideo();
        if (drivePlayer && data.video_source === 'drive') drivePlayer.play();

        priorityVideo.removeEventListener('ended', endAd);
    };

    priorityVideo.addEventListener('ended', endAd);
    setTimeout(endAd, pauseMs);
}

function extractYoutubeId(url) {
    if (!url) return null;
    // Enhanced regex to handle watch?v=, embeds, shorts, youtu.be, and complex URLs with params
    const regex = /(?:youtube\.com\/(?:[^\/]+\/.+\/|(?:v|e(?:mbed)?|shorts)\/|.*[?&]v=)|youtu\.be\/)([^"&?\/\s]{11})/;
    const match = url.match(regex);
    return (match && match[1]) ? match[1] : null;
}

// Keep helper for consistency if needed, but transformDriveImgUrl is preferred
function transformDriveUrl(url) {
    return transformDriveImgUrl(url);
}

function startSidebarRotation() {
    if (rotationInterval) clearInterval(rotationInterval);
    const slots = [
        document.getElementById("sidebar-slot-1"),
        document.getElementById("sidebar-slot-2"),
        document.getElementById("sidebar-slot-3")
    ];

    const ds = window.currentConfig?.design_settings || {};
    const layout = ds.sidebar_layout || 1;

    // Apply Visibility based on layout
    slots.forEach((slot, i) => {
        if (!slot) return;
        slot.style.display = (i < layout) ? 'flex' : 'none';
        // Reset styles for clean state
        slot.style.opacity = '1';
        slot.style.transform = 'translateY(0)';
    });

    // Prepare "Pages" or "Groups"
    // The new Admin UI saves a flat list of N blocks matching the layout.
    // We treat this as a SINGLE group.

    let currentBlocks = [...sidebarItems];

    // Safety check: ensure we have blocks for the layout
    while (currentBlocks.length < layout) {
        currentBlocks.push({ type: 'text', value: '', color: 'transparent' });
    }

    // Animation Loop
    const animateBlocks = () => {
        // Phase 1: Fade Out
        slots.forEach(slot => {
            if (slot && slot.style.display !== 'none') {
                slot.style.opacity = '0';
                slot.style.transform = 'translateY(10px)';
            }
        });

        setTimeout(() => {
            // Phase 2: Update Content
            slots.forEach((slot, i) => {
                if (i >= layout || !slot) return;
                slot.innerHTML = '';

                const item = currentBlocks[i];
                if (item) {
                    const wrapper = document.createElement('div');
                    wrapper.style.width = '100%';
                    wrapper.style.height = '100%';
                    wrapper.style.display = 'flex';
                    wrapper.style.justifyContent = 'center';
                    wrapper.style.alignItems = 'center';

                    if (item.type === 'image') {
                        const img = document.createElement('img');
                        img.src = transformDriveImgUrl(item.value);
                        img.className = 'anim-zoom';
                        img.style.width = '100%';
                        img.style.height = '100%';
                        img.style.objectFit = 'contain';
                        img.style.borderRadius = '12px';

                        // Dynamic Height adjustments
                        const maxH = layout === 1 ? '70vh' : (layout === 2 ? '35vh' : '23vh');
                        img.style.maxHeight = maxH;

                        wrapper.appendChild(img);
                    } else {
                        const txt = document.createElement('div');
                        txt.className = 'anim-slide';
                        txt.innerText = item.value;
                        txt.style.color = item.color || 'var(--sidebar-text, #fff)';
                        // Font Size Boost for single block
                        txt.style.fontSize = item.font_size || (layout === 1 ? '2.5rem' : '1.4rem');
                        txt.style.fontWeight = item.weight || 'bold';
                        txt.style.fontFamily = item.font_family || 'inherit';
                        txt.style.textAlign = 'center';
                        txt.style.whiteSpace = 'pre-wrap';
                        wrapper.appendChild(txt);
                    }
                    slot.appendChild(wrapper);
                }
            });

            // Phase 3: Cascade Fade In
            slots.forEach((slot, i) => {
                if (i >= layout || !slot) return;
                setTimeout(() => {
                    slot.style.opacity = '1';
                    slot.style.transform = 'translateY(0)';
                }, i * 300);
            });

        }, 800);
    };

    animateBlocks();
    // Loop every N seconds (default 15s) to refresh/animate
    const duration = window.currentConfig?.pause_duration || 15;
    rotationInterval = setInterval(animateBlocks, duration * 1000);
}

function updateBottomBar() {
    const wrapper = document.getElementById("ticker-wrapper");
    if (!wrapper) return;
    wrapper.innerHTML = ""; // Clean

    // Build items array
    const items = [];
    const ds = window.currentConfig?.design_settings || {};

    // Common Font Settings for Ticker
    const tickerStyle = {
        color: ds.ticker_color || bottomData.color || "var(--ticker-text-color)",
        fontSize: bottomData.font_size || "1.2rem",
        fontWeight: bottomData.weight || "bold",
        fontFamily: ds.ticker_font || 'inherit'
    };

    // 1. Multiple Scrolling Messages (Ticker)
    const msgs = Array.isArray(bottomData.messages) ? bottomData.messages : [bottomData.static || "Venrides Pantallas Inteligentes"];

    msgs.forEach(text => {
        items.push({
            type: 'text',
            content: text,
            style: {
                ...tickerStyle,
                marginRight: "6vw"
            }
        });
    });

    // 4. Inject Ad Scripts (Google/Meta if provided)
    const configData = window.currentConfig || {};
    if (configData.ad_scripts && Array.isArray(configData.ad_scripts)) {
        configData.ad_scripts.forEach(scriptCode => {
            if (!document.querySelector(`[data-ad-script="${btoa(scriptCode).substring(0, 20)}"]`)) {
                const container = document.createElement('div');
                container.setAttribute('data-ad-script', btoa(scriptCode).substring(0, 20));
                container.innerHTML = scriptCode;
                document.body.appendChild(container);

                // Re-execute scripts if any were injected via innerHTML
                const scripts = container.querySelectorAll('script');
                scripts.forEach(s => {
                    const newScript = document.createElement('script');
                    if (s.src) newScript.src = s.src;
                    else newScript.textContent = s.textContent;
                    document.head.appendChild(newScript);
                });
            }
        });
    }

    // 2. BCV Rate
    if (bcvRate > 0 && ds.show_bcv !== false) {
        items.push({
            type: 'html',
            content: `<span style="opacity:0.8; margin-right:5px;">BCV:</span> <span style="font-size: ${ds.bcv_size || '1.4rem'}; color: ${ds.bcv_color || '#fbbf24'}; font-weight: ${ds.bcv_weight || 'bold'}; font-family: ${ds.bcv_font || 'inherit'};">Bs. ${bcvRate.toFixed(2)}</span>`,
            style: {
                marginRight: "4vw",
                fontWeight: "bold",
                display: "inline-flex",
                alignItems: "center"
            }
        });
    }

    // 3. Social Media
    const socialStyle = {
        color: ds.ticker_color || 'white',
        fontSize: bottomData.social_font_size || '1.4rem',
        fontWeight: bottomData.social_weight || 'normal',
        fontFamily: ds.ticker_font || 'inherit',
        marginRight: "4vw",
        display: "inline-flex",
        alignItems: "center",
        gap: "0.5rem"
    };

    // SVGs
    const iconWhatsapp = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24" fill="currentColor"><path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347m-5.421 7.403h-.004a9.87 9.87 0 01-5.031-1.378l-.361-.214-3.741.982.998-3.648-.235-.374a9.86 9.86 0 01-1.51-5.26c.001-5.45 4.436-9.884 9.888-9.884 2.64 0 5.122 1.03 6.988 2.898a9.825 9.825 0 012.893 6.994c-.003 5.45-4.437 9.884-9.885 9.884m8.413-18.297A11.815 11.815 0 0012.05 0C5.495 0 .16 5.335.157 11.892c0 2.096.547 4.142 1.588 5.945L.057 24l6.305-1.654a11.882 11.882 0 005.683 1.448h.005c6.554 0 11.89-5.335 11.893-11.893a11.821 11.821 0 00-3.48-8.413Z"/></svg>`;
    const iconInstagram = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24" fill="currentColor"><path d="M12 2.163c3.204 0 3.584.012 4.85.07 3.252.148 4.771 1.691 4.919 4.919.058 1.265.069 1.645.069 4.849 0 3.205-.012 3.584-.069 4.849-.149 3.225-1.664 4.771-4.919 4.919-1.266.058-1.644.07-4.85.07-3.204 0-3.584-.012-4.849-.07-3.26-.149-4.771-1.699-4.919-4.92-.058-1.265-.07-1.644-.07-4.849 0-3.204.013-3.583.07-4.849.149-3.227 1.664-4.771 4.919-4.919 1.266-.057 1.645-.069 4.849-.069zM12 0C8.741 0 8.333.014 7.053.072 2.695.272.273 2.69.073 7.052.014 8.333 0 8.741 0 12c0 3.259.014 3.668.072 4.948.2 4.358 2.618 6.78 6.98 6.98C8.333 23.986 8.741 24 12 24c3.259 0 3.668-.014 4.948-.072 4.354-.2 6.782-2.618 6.979-6.98.059-1.28.073-1.689.073-4.948 0-3.259-.014-3.667-.072-4.947-.196-4.354-2.617-6.78-6.979-6.98C15.668.014 15.259 0 12 0zm0 5.838a6.162 6.162 0 100 12.324 6.162 6.162 0 000-12.324zM12 16a4 4 0 110-8 4 4 0 010 8zm6.406-11.845a1.44 1.44 0 100 2.881 1.44 1.44 0 000-2.881z"/></svg>`;

    if (bottomData.whatsapp) {
        items.push({
            type: 'html',
            content: `<span style="color: #25D366; display: flex;">${iconWhatsapp}</span> <span>${bottomData.whatsapp}</span>`,
            style: socialStyle
        });
    }

    if (bottomData.instagram) {
        items.push({
            type: 'html',
            content: `<span style="color: #E1306C; display: flex;">${iconInstagram}</span> <span>@${bottomData.instagram}</span>`,
            style: socialStyle
        });
    }

    // Render items to wrapper
    // We duplicate items to fill space if needed, but for infinite loop CSS we just need enough content.
    // CSS animation 'tickerMove' handles the scroll. Ideally we duplicate content to ensure smooth loop.
    const contentNodes = [];

    items.forEach(item => {
        const el = document.createElement("div");
        el.className = "ticker-item";
        if (item.type === 'html') el.innerHTML = item.content;
        else el.innerText = item.content;

        Object.assign(el.style, item.style);
        wrapper.appendChild(el);
        contentNodes.push(el.cloneNode(true)); // Keep copy for duplication
    });

    // Duplicate content once to ensure seamless loop
    contentNodes.forEach(node => wrapper.appendChild(node));
}

function handleAlert(alert) {
    if (!alert) return;
    if (isAlertShowing) return;
    if (alert.id === lastAlertId) return;

    showAlert(alert);
}

function handlePing(shouldPing, deviceName) {
    if (!shouldPing) return;

    const overlay = document.getElementById("ping-overlay");
    const nameEl = document.getElementById("ping-device-name");

    if (overlay && nameEl) {
        nameEl.innerText = deviceName || "Este Dispositivo";
        overlay.classList.remove("hidden");

        // Hide after 10s
        setTimeout(() => {
            overlay.classList.add("hidden");
        }, 10000);
    }
}

function showAlert(alert) {
    const overlay = document.getElementById("alert-overlay");
    const body = document.getElementById("alert-body");
    const title = document.getElementById("alert-title");

    if (!overlay || !body) return;

    lastAlertId = alert.id;
    isAlertShowing = true;
    body.innerText = alert.body;
    if (alert.subject) title.innerText = alert.subject;

    overlay.classList.remove("hidden");
    console.log("Showing Live Alert:", alert);

    setTimeout(() => {
        hideAlert();
    }, (alert.duration || 15) * 1000);
}

function hideAlert() {
    const overlay = document.getElementById("alert-overlay");
    if (overlay) overlay.classList.add("hidden");
    isAlertShowing = false;
    console.log("Alert hidden.");
}

function showSuspended() {
    document.getElementById("kill-switch").classList.remove("hidden");
}

function showBlockingScreen() {
    const reg = document.getElementById("registration-overlay");
    if (!reg) return;
    reg.classList.remove("hidden");
    reg.innerHTML = `
        <div class="registration-box" style="border-color: #ef4444;">
            <div style="margin-bottom: 1rem;">
                <img src="venrides_logo.png" alt="VenridesScreenS" style="height: 150px; object-fit: contain; filter: drop-shadow(0 0 10px rgba(0,0,0,0.5));" />
            </div>
            <h1 style="color: #ef4444; margin-bottom: 1rem; font-size: 2.5rem;">⚠️ DISPOSITIVO BLOQUEADO</h1>
            <p style="font-size: 1.4rem; color: #fff; margin-bottom: 2rem;">
                Este dispositivo ya agotó su prueba gratuita anteriormente.<br/>
                Para continuar disfrutando del servicio, por favor suscríbete a un plan de pago.
            </p>
            <div style="background: rgba(239, 68, 68, 0.1); padding: 1rem; border-radius: 8px; border: 1px solid #ef4444; color: #ef4444; font-weight: bold;">
                Error: FREE_TRIAL_LIMIT_REACHED
            </div>
            <p style="margin-top: 2rem; font-size: 0.9rem; opacity: 0.7;">
                ID: ${deviceUuid}
            </p>
        </div>
    `;
}

function showRegistrationScreen() {
    const reg = document.getElementById("registration-overlay");
    if (!reg) return;
    reg.classList.remove("hidden");
    reg.innerHTML = `
        <div class="registration-box">
            <div style="margin-bottom: 2rem;">
                <img src="venrides_logo.png" alt="VenridesScreenS" style="height: 180px; object-fit: contain; filter: drop-shadow(1px 1px 0 #fff) drop-shadow(-1px -1px 0 #fff) drop-shadow(1px -1px 0 #fff) drop-shadow(-1px 1px 0 #fff) drop-shadow(0 5px 15px rgba(0,0,0,0.4));" />
            </div>
            <h2 style="color: #10b981; margin-bottom: 1.5rem;">Vincular Pantalla</h2>
            <p style="margin-bottom: 0.5rem;">ID del Dispositivo:</p>
            <div style="background:#222; padding:1.2rem; border-radius:12px; font-family:monospace; font-size:1.1rem; margin-bottom:1.5rem; word-break:break-all; border: 1px solid #333; color: #aaa;">
                ${deviceUuid}
            </div>
            <p style="margin-bottom: 0.5rem;">O ingresa el código de 6 dígitos:</p>
            <div class="code-input-container" style="display:flex; justify-content:center; gap:10px;">
                <input type="text" id="reg-code-input" maxlength="6" placeholder="000000" style="background:#222; border:2px solid #444; color:#10b981; font-size:1.8rem; text-align:center; width:160px; border-radius:10px; outline:none;"/>
                <button id="reg-submit-btn" style="background:#10b981; border:none; padding:0 25px; border-radius:10px; font-weight:bold; cursor:pointer; color:#000; font-size:1.1rem; transition: transform 0.2s;">VINCULAR</button>
            </div>
            <p style="margin-top: 1.5rem; font-size: 1rem; color: #10b981; font-weight: bold; animation: pulse 2s infinite;">
                Esperando vinculación...
            </p>
        </div>
    `;

    document.getElementById("reg-submit-btn").onclick = async () => {
        const code = document.getElementById("reg-code-input").value;
        if (code.length !== 6) return;
        try {
            const res = await fetch(`${API_URL}/devices/validate-code?code=${code}&device_uuid=${deviceUuid}`, { method: 'POST' });
            if (res.ok) {
                const data = await res.json();
                applyBranding(data);
            } else {
                const errData = await res.json();
                if (errData.detail === "DEVICE_BLOCKED_FREE_TRIAL_USED") {
                    showBlockingScreen();
                } else {
                    alert("Código inválido o expirado");
                }
            }
        } catch (e) {
            console.error("Link Error:", e);
            alert("Error de conexión");
        }
    };
}
