import React, { useState, useEffect } from 'react';
import { Upload, Palette, Monitor, Power, CheckCircle2, AlertCircle, Lock, Layout, Info, LogOut, ShieldCheck, HardDrive, Building, DollarSign, Users, Trash2, Edit, Eye, Plus, X, CreditCard, Calendar, Key, PlaySquare, MessageSquare, Check, Sun, Moon, Bell, Shield, Image, Type, Mail, PlayCircle, Clock, LifeBuoy, XCircle, CheckCircle, Send, Wifi, BarChart, Activity, ShoppingCart, Gift, Target } from 'lucide-react';
import ChatPanel from './components/ChatPanel';

const API_BASE = import.meta.env.VITE_API_BASE_URL || "/api";

// --- HELPERS ---
const safeParse = (str, fallback = {}) => {
    try {
        if (!str || str === "undefined") return fallback;
        return JSON.parse(str);
    } catch (e) {
        console.error("JSON Parse Error:", e);
        return fallback;
    }
};

const getContrastColor = (hex) => {
    try {
        if (!hex) return '#ffffff';
        const r = parseInt(hex.substring(1, 3), 16);
        const g = parseInt(hex.substring(3, 5), 16);
        const b = parseInt(hex.substring(5, 7), 16);
        return ((r * 299) + (g * 587) + (b * 114)) / 1000 >= 128 ? '#000000' : '#ffffff';
    } catch { return '#ffffff'; }
};

const Tooltip = ({ text, children }) => (
    <div className="premium-tooltip">
        {children || <Info size={14} className="info-icon" style={{ opacity: 0.5 }} />}
        <span className="tooltip-text">{text}</span>
    </div>
);

const Modal = ({ isOpen, onClose, title, children }) => {
    if (!isOpen) return null;
    return (
        <div className="modal-overlay" onClick={onClose}>
            <div className="modal-content glass-card" onClick={(e) => e.stopPropagation()} style={{ border: '1px solid rgba(255,255,255,0.1)', backdropFilter: 'blur(16px)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
                    <h2 style={{ fontSize: '1.3rem', fontWeight: 'bold', color: 'var(--primary-color)' }}>{title}</h2>
                    <button onClick={onClose} className="btn" style={{ padding: '0.5rem' }}><X size={20} /></button>
                </div>
                {children}
            </div>
        </div>
    );
};

// Global Tooltip Styles
const GlobalStyles = () => (
    <style>{`
        .premium-tooltip {
            position: relative;
            display: inline-block;
        }
        .premium-tooltip .tooltip-text {
            visibility: hidden;
            width: 180px;
            background-color: rgba(15, 23, 42, 0.95);
            color: #fff;
            text-align: center;
            border-radius: 8px;
            padding: 8px 12px;
            position: absolute;
            z-index: 1000;
            bottom: 125%;
            left: 50%;
            margin-left: -90px;
            opacity: 0;
            transition: opacity 0.3s, visibility 0.3s, transform 0.3s;
            transform: translateY(10px);
            font-size: 0.75rem;
            line-height: 1.4;
            border: 1px solid rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(12px);
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);
            pointer-events: none;
        }
        .premium-tooltip:hover .tooltip-text {
            visibility: visible;
            opacity: 1;
            transform: translateY(0);
        }
        .premium-tooltip .tooltip-text::after {
            content: "";
            position: absolute;
            top: 100%;
            left: 50%;
            margin-left: -5px;
            border-width: 5px;
            border-style: solid;
            border-color: rgba(15, 23, 42, 0.95) transparent transparent transparent;
        }

        /* Sidebar Layout - New Admin UI */
        .admin-dashboard-layout {
            display: flex;
            min-height: 100vh;
            background: var(--bg-app);
            color: var(--text-main);
        }
        .admin-sidebar {
            width: 280px;
            background: var(--card-bg);
            border-right: 1px solid var(--border-color);
            display: flex;
            flex-direction: column;
            position: sticky;
            top: 0;
            height: 100vh;
            z-index: 100;
            transition: all 0.3s;
        }
        .sidebar-header-custom {
            padding: 2rem 1.5rem;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            flex-direction: column;
            align-items: center;
            text-align: center;
            gap: 1rem;
        }
        .sidebar-content-custom {
            flex: 1;
            overflow-y: auto;
            padding: 1rem 0;
        }
        .sidebar-group-custom {
            margin-bottom: 1.2rem;
        }
        .sidebar-group-title-custom {
            padding: 0 1.5rem;
            font-size: 0.65rem;
            font-weight: 800;
            color: var(--primary-color);
            text-transform: uppercase;
            letter-spacing: 0.08rem;
            margin-bottom: 0.6rem;
            opacity: 0.7;
        }
        .sidebar-item-custom {
            display: flex;
            align-items: center;
            gap: 1rem;
            padding: 0.8rem 1.5rem;
            color: var(--text-main);
            text-decoration: none;
            cursor: pointer;
            transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
            border-left: 4px solid transparent;
            font-size: 0.92rem;
            background: none;
            border: none;
            width: 100%;
            text-align: left;
            opacity: 0.85;
        }
        .sidebar-item-custom:hover {
            background: rgba(255,255,255,0.03);
            color: var(--primary-color);
            opacity: 1;
            padding-left: 1.7rem;
        }
        .sidebar-item-custom.active {
            background: rgba(var(--primary-rgb, 107, 70, 193), 0.1);
            color: var(--primary-color);
            border-left-color: var(--primary-color);
            font-weight: 600;
            opacity: 1;
        }
        .sidebar-badge-custom {
            background: #f43f5e;
            color: white;
            padding: 1px 6px;
            border-radius: 10px;
            font-size: 0.7rem;
            font-weight: bold;
        }
        .sidebar-footer-custom {
            padding: 1rem;
            border-top: 1px solid var(--border-color);
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }
        .admin-main-content {
            flex: 1;
            padding: 2rem;
            max-width: 1400px;
            margin: 0 auto;
            width: 100%;
        }
        @media (max-width: 1024px) {
            .admin-sidebar { width: 80px; }
            .sidebar-group-title-custom, .sidebar-item-custom span { display: none; }
            .sidebar-item-custom { justify-content: center; padding: 1rem; }
        }
    `}</style>
);


// Helper for Drive Images
const transformDriveImgUrl = (url) => {
    if (!url) return "";
    try {
        if (url.includes("drive.google.com") || url.includes("docs.google.com")) {
            const idMatch = url.match(/(?:\/d\/|id=|open\?id=)([-\w]{15,})/) || url.match(/([-\w]{25,})/);
            if (idMatch && idMatch[1]) {
                const id = idMatch[1];
                return `https://lh3.googleusercontent.com/d/${id}=w1000?authuser=0`;
            }
        }
    } catch (e) { console.error("URL transform error", e); }
    return url;
}; // End Helper

function App() {
    const [token, setToken] = useState(localStorage.getItem('token'));
    const [view, setView] = useState('login'); // login, superadmin, client, operator
    const [userRole, setUserRole] = useState(localStorage.getItem('user_role') || '');
    const [userPermissions, setUserPermissions] = useState(safeParse(localStorage.getItem('user_permissions'), {}));
    const [adminTab, setAdminTab] = useState('companies'); // companies, users, devices, payments, global_ad, stats
    const [clientTab, setClientTab] = useState('profile'); // profile, management, appearance, sidebar_tab, bottombar_tab, videos
    const [barSubTab, setBarSubTab] = useState('sidebar'); // sidebar, bottom
    const [theme, setTheme] = useState(localStorage.getItem('theme') || 'dark');
    const [company, setCompany] = useState(null);
    const [companies, setCompanies] = useState([]);
    const [payments, setPayments] = useState([]);
    const [users, setUsers] = useState([]);
    const [allDevices, setAllDevices] = useState([]);
    const [stats, setStats] = useState(null);
    const [loading, setLoading] = useState(false);
    const [credentials, setCredentials] = useState({ username: '', password: '' });
    const userObj = safeParse(localStorage.getItem('user'), {});
    const isAdmin = userObj?.is_admin || userObj?.role === 'admin_master';
    const isMaster = userObj?.role === 'admin_master';

    // Modal states
    const [showCompanyModal, setShowCompanyModal] = useState(false);
    const [showPaymentModal, setShowPaymentModal] = useState(false);
    const [showDetailsModal, setShowDetailsModal] = useState(false);
    const [codeModalData, setCodeModalData] = useState(null); // Nuevo estado para el modal de código
    const [selectedCompany, setSelectedCompany] = useState(null);
    const [companyDevices, setCompanyDevices] = useState([]);
    const [detailsPayments, setDetailsPayments] = useState([]);

    // New Modals State (to replace native confirms/alerts)
    const [confirmModalData, setConfirmModalData] = useState(null); // { title, message, onConfirm, confirmText, cancelText, type: 'danger'|'info' }
    const [alertModalData, setAlertModalData] = useState(null); // { title, message, type: 'success'|'error'|'info' }

    // Admin Impersonation State
    const [impersonatingCompanyId, setImpersonatingCompanyId] = useState(null);

    // Local State for Client Editor (Explicit Save)
    const [localCompany, setLocalCompany] = useState(null);
    const [unsavedChanges, setUnsavedChanges] = useState(false);
    const [showCompanyForm, setShowCompanyForm] = useState(false);
    const [showAdminPassModal, setShowAdminPassModal] = useState(false);
    const [showUserModal, setShowUserModal] = useState(false);
    const [editingUser, setEditingUser] = useState(null);
    const [bcvRate, setBcvRate] = useState(null);
    const [ytReady, setYtReady] = useState(false);

    // Remember Me & Password Recovery
    const [rememberMe, setRememberMe] = useState(false);
    const [showForgotPassword, setShowForgotPassword] = useState(false);
    const [showChangePassword, setShowChangePassword] = useState(false);
    const [recoveryEmail, setRecoveryEmail] = useState('');
    const [passwordChange, setPasswordChange] = useState({ old: '', new: '', confirm: '' });

    // Device Management State
    const [editingDevice, setEditingDevice] = useState(null);
    const [renameDeviceName, setRenameDeviceName] = useState('');
    const [supportUnreadCount, setSupportUnreadCount] = useState(0);

    useEffect(() => {
        document.documentElement.setAttribute('data-theme', theme);
        localStorage.setItem('theme', theme);
    }, [theme]);

    // Force logout when accessed with ?logout=true parameter (security feature from landing page)
    useEffect(() => {
        const params = new URLSearchParams(window.location.search);
        if (params.get('logout') === 'true') {
            localStorage.clear();
            setToken(null);
            setView('login');
            setCompany(null);
            setLocalCompany(null);
            setUserRole('');
            setUserPermissions({});
            // Remove parameter from URL without reload
            window.history.replaceState({}, document.title, window.location.pathname);
        }
    }, []);

    const handleLogout = () => {
        localStorage.clear();
        setToken(null);
        setView('login');
        setCompany(null);
        setLocalCompany(null);
        setUserRole('');
        setUserPermissions({});
    };

    const handleLogin = async (e) => {
        e.preventDefault();
        setLoading(true);
        try {
            const res = await fetch(`${API_BASE}/login/token`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams({ username: credentials.username, password: credentials.password })
            });

            const data = await res.json();
            if (res.ok) {
                // Save credentials if remember me is checked
                if (rememberMe) {
                    localStorage.setItem('remembered_username', credentials.username);
                    localStorage.setItem('remembered_password', btoa(credentials.password));
                } else {
                    localStorage.removeItem('remembered_username');
                    localStorage.removeItem('remembered_password');
                }

                localStorage.setItem('token', data.access_token);
                localStorage.setItem('user', JSON.stringify(data.user));
                localStorage.setItem('user_role', data.user.role);
                localStorage.setItem('user_permissions', JSON.stringify(data.user.permissions || {}));

                setToken(data.access_token);
                setUserRole(data.user.role);
                setUserPermissions(data.user.permissions || {});

                // Check if must change password
                if (data.user.must_change_password) {
                    setShowChangePassword(true);
                }

                let targetView = 'client';
                if (data.user.role === 'admin_master') targetView = 'superadmin';
                else if (data.user.role === 'operador_empresa') targetView = 'operator';
                else if (data.user.role === 'admin_empresa') targetView = 'client';

                setView(targetView);
                fetchInitialData(targetView);
            } else {
                setAlertModalData({ title: "Error", message: data.detail || "Error al iniciar sesión", type: "error" });
            }
        } catch (err) {
            setAlertModalData({ title: "Error", message: "Error de conexión", type: "error" });
        } finally {
            setLoading(false);
        }
    };

    const toggleTheme = () => setTheme(prev => prev === 'dark' ? 'light' : 'dark');

    // Auto-logout on inactivity (10 minutes)
    useEffect(() => {
        if (view === 'login') return;

        let inactivityTimer;
        const INACTIVITY_TIMEOUT = 600000; // 10 minutes

        const resetTimer = () => {
            clearTimeout(inactivityTimer);
            inactivityTimer = setTimeout(() => {
                // Auto logout
                localStorage.clear();
                setView('login');
                setToken(null);
                alert('Sesión cerrada por inactividad');
            }, INACTIVITY_TIMEOUT);
        };

        // Activity events
        const events = ['mousedown', 'keydown', 'scroll', 'touchstart', 'mousemove'];
        events.forEach(e => window.addEventListener(e, resetTimer));
        resetTimer();

        return () => {
            clearTimeout(inactivityTimer);
            events.forEach(e => window.removeEventListener(e, resetTimer));
        };
    }, [view]);

    // Load remembered credentials
    useEffect(() => {
        const savedUsername = localStorage.getItem('remembered_username');
        const savedPassword = localStorage.getItem('remembered_password');
        if (savedUsername) {
            setCredentials(prev => ({ ...prev, username: savedUsername }));
            if (savedPassword) {
                setCredentials(prev => ({ ...prev, password: atob(savedPassword) }));
                setRememberMe(true);
            }
        }
    }, []);

    useEffect(() => {
        if (!window.YT) {
            const tag = document.createElement('script');
            tag.src = "https://www.youtube.com/iframe_api";
            const firstScriptTag = document.getElementsByTagName('script')[0];
            firstScriptTag.parentNode.insertBefore(tag, firstScriptTag);
            window.onYouTubeIframeAPIReady = () => setYtReady(true);
        } else {
            setYtReady(true);
        }
    }, []);

    useEffect(() => {
        fetch(`${API_BASE}/finance/bcv`)
            .then(res => res.json())
            .then(data => {
                if (data.usd_to_ves) setBcvRate(data.usd_to_ves);
            })
            .catch(err => console.error("BCV Error:", err));
    }, []);

    useEffect(() => {
        if (!token) return;
        const fetchUnread = async () => {
            try {
                const res = await fetch(`${API_BASE}/support/unread-count`, {
                    headers: { 'Authorization': `Bearer ${token}` }
                });
                if (res.ok) {
                    const data = await res.json();
                    setSupportUnreadCount(data.count || 0);
                }
            } catch (e) {
                console.error("Error fetching unread count", e);
            }
        };

        fetchUnread();
        const interval = setInterval(fetchUnread, 60000); // 1 min pulse
        return () => clearInterval(interval);
    }, [token]);

    const fetchInitialData = async (roleOverride = null) => {
        if (!token) return;
        setLoading(true);
        const role = roleOverride || (view === 'login' ? (JSON.parse(localStorage.getItem('user') || '{}')?.is_admin ? 'superadmin' : 'client') : view);

        try {
            const headers = { 'Authorization': `Bearer ${token}` };

            if (role === 'superadmin') {
                const res = await fetch(`${API_BASE}/companies/`, { headers });
                if (res.status === 401) {
                    handleLogout();
                    return;
                }
                const data = await res.json();
                setCompanies(Array.isArray(data) ? data : []);

                const statsRes = await fetch(`${API_BASE}/admin/stats/overview`, { headers });
                if (statsRes.ok) {
                    const statsData = await statsRes.json();
                    setStats(statsData);
                }

                const paymentsRes = await fetch(`${API_BASE}/admin/payments/`, { headers });
                if (paymentsRes.ok) {
                    const paymentsData = await paymentsRes.json();
                    setPayments(Array.isArray(paymentsData) ? paymentsData : []);
                }

                const usersRes = await fetch(`${API_BASE}/admin/users/`, { headers });
                if (usersRes.ok) {
                    const usersData = await usersRes.json();
                    setUsers(Array.isArray(usersData) ? usersData : []);
                }

                const devicesRes = await fetch(`${API_BASE}/admin/devices/`, { headers });
                if (devicesRes.ok) {
                    const devicesData = await devicesRes.json();
                    setAllDevices(Array.isArray(devicesData) ? devicesData : []);
                }
            } else if (role === 'client') {
                const storedUser = JSON.parse(localStorage.getItem('user') || '{}');
                const targetId = impersonatingCompanyId || storedUser.company_id;

                if (!targetId) {
                    setLoading(false);
                    return;
                }

                const res = await fetch(`${API_BASE}/companies/${targetId}`, { headers });
                if (res.status === 401) {
                    handleLogout();
                    return;
                }
                const data = await res.json();
                setCompany(data);
                setLocalCompany(data);
                setUnsavedChanges(false);

                // Fetch devices
                const devRes = await fetch(`${API_BASE}/admin/companies/${targetId}/devices`, { headers });
                if (devRes.ok) {
                    const devData = await devRes.json();
                    setCompanyDevices(Array.isArray(devData) ? devData : []);
                }

                // Fetch users for this company (scoped by backend)
                const usersRes = await fetch(`${API_BASE}/admin/users/`, { headers });
                if (usersRes.ok) {
                    const usersData = await usersRes.json();
                    setUsers(Array.isArray(usersData) ? usersData : []);
                }
            }
        } catch (err) {
            console.error("Fetch Error:", err);
            handleLogout();
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        if (token) {
            const storedUser = safeParse(localStorage.getItem('user'), {});
            const role = localStorage.getItem('user_role');

            if (!role || !storedUser) {
                console.warn("Incomplete session detected. Clearing storage.");
                handleLogout();
                return;
            }

            let targetView = 'login';
            if (role === 'admin_master') {
                targetView = 'superadmin';
            } else if (role === 'admin_empresa' || role === 'user_basic') {
                targetView = 'client';
            } else if (role === 'operador_empresa') {
                targetView = 'operator';
            } else {
                localStorage.clear();
            }

            setView(targetView);
            fetchInitialData(targetView);
        } else {
            setView('login');
        }
    }, [token]);

    // Silent Refresh for Devices (Polling)
    const refreshDevices = async () => {
        if (!token) return;
        const role = view === 'login' ? (JSON.parse(localStorage.getItem('user') || '{}')?.is_admin ? 'superadmin' : 'client') : view;
        const headers = { 'Authorization': `Bearer ${token}` };

        try {
            if (role === 'superadmin') {
                const devicesRes = await fetch(`${API_BASE}/admin/devices/`, { headers });
                const devicesData = await devicesRes.json();
                if (Array.isArray(devicesData)) setAllDevices(devicesData);
            } else if (role === 'client') {
                const storedUser = JSON.parse(localStorage.getItem('user') || '{}');
                const targetId = impersonatingCompanyId || storedUser.company_id;
                if (targetId) {
                    const devRes = await fetch(`${API_BASE}/admin/companies/${targetId}/devices`, { headers });
                    const devData = await devRes.json();
                    setCompanyDevices(Array.isArray(devData) ? devData : []);
                }
            }
        } catch (err) {
            console.error("Silent Refresh Error:", err);
        }
    };

    useEffect(() => {
        if (!token) return;
        const intervalId = setInterval(refreshDevices, 10000); // Poll every 10s
        return () => clearInterval(intervalId);
    }, [token, view, impersonatingCompanyId]);


    const deleteDevice = async (uuid, force = false) => {
        if (!force) {
            setConfirmModalData({
                title: "Eliminar Dispositivo",
                message: "¿Seguro que deseas eliminar este dispositivo? Esta acción no se puede deshacer.",
                confirmText: "Eliminar",
                type: "danger",
                onConfirm: () => deleteDevice(uuid, true)
            });
            return;
        }

        try {
            const res = await fetch(`${API_BASE}/admin/devices/${uuid}`, {
                method: 'DELETE',
                headers: { 'Authorization': `Bearer ${token}` }
            });

            if (res.ok) {
                setAllDevices(allDevices.filter(d => d.uuid !== uuid));
                await fetchInitialData();
                setAlertModalData({ title: "Éxito", message: "Dispositivo eliminado", type: "success" });
            } else {
                const data = await res.json();
                throw new Error(data.detail || "Error al eliminar");
            }
        } catch (err) {
            console.error('deleteDevice error:', err);
            setAlertModalData({ title: "Error", message: err.message, type: "error" });
        }
    };

    const toggleDeviceStatus = async (device, force = false) => {
        if (!force && device.is_active) {
            setConfirmModalData({
                title: "Suspender Pantalla",
                message: "¿Desea suspender esta pantalla? Dejará de mostrar contenido.",
                confirmText: "Suspender",
                type: "danger",
                onConfirm: () => toggleDeviceStatus(device, true)
            });
            return;
        }

        try {
            const newStatus = !device.is_active;
            const res = await fetch(`${API_BASE}/admin/devices/${device.uuid}/status?is_active=${newStatus}`, {
                method: 'PATCH',
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (res.ok) {
                await fetchInitialData();
            } else {
                const data = await res.json();
                setAlertModalData({ title: "Error", message: data.detail || "Error al cambiar estado", type: "error" });
            }
        } catch (e) {
            setAlertModalData({ title: "Error", message: "Error al cambiar estado: " + e.message, type: "error" });
        }
    };

    const deletePayment = async (id, force = false) => {
        if (!force) {
            setConfirmModalData({
                title: "Eliminar Pago",
                message: "¿Seguro que deseas eliminar este registro de pago?",
                confirmText: "Eliminar",
                type: "danger",
                onConfirm: () => deletePayment(id, true)
            });
            return;
        }

        try {
            const res = await fetch(`${API_BASE}/admin/payments/${id}`, {
                method: 'DELETE',
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (res.ok) {
                setPayments(payments.filter(p => p.id !== id));
                setAlertModalData({ title: "Éxito", message: "Pago eliminado", type: "success" });
            }
        } catch (err) { console.error(err); }
    };

    const handleRenameClick = (device) => {
        setEditingDevice(device);
        setRenameDeviceName(device.name);
    };

    const handleRenameSubmit = async () => {
        if (!editingDevice || !renameDeviceName.trim()) return;
        try {
            const res = await fetch(`${API_BASE}/devices/${editingDevice.uuid}/rename`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
                body: JSON.stringify({ name: renameDeviceName })
            });
            if (!res.ok) throw new Error("Error al renombrar");

            // Update local state
            const updateState = (list) => list.map(d => d.uuid === editingDevice.uuid ? { ...d, name: renameDeviceName } : d);
            setAllDevices(updateState(allDevices));
            if (companyDevices.length > 0) setCompanyDevices(updateState(companyDevices));

            setEditingDevice(null);
            setAlertModalData({ title: "Éxito", message: "Dispositivo renombrado", type: "success" });
        } catch (e) {
            setAlertModalData({ title: "Error", message: e.message, type: "error" });
        }
    };

    const unlinkAllDevices = async (targetCompanyId) => {
        setConfirmModalData({
            title: "Desvincular TODAS las Pantallas",
            message: "⚠️ ¿ESTÁ SEGURO? Esta acción eliminará y desvinculará TODAS las pantallas de esta empresa. Tendrán que ser registradas nuevamente. Esta acción es irreversible.",
            confirmText: "DESVINCULAR TODO",
            type: "danger",
            onConfirm: async () => {
                try {
                    const res = await fetch(`${API_BASE}/admin/companies/${targetCompanyId}/devices`, {
                        method: 'DELETE',
                        headers: { 'Authorization': `Bearer ${token}` }
                    });
                    if (!res.ok) throw new Error("Error al desvincular");

                    if (view === 'superadmin') {
                        setAllDevices(allDevices.filter(d => d.company_id !== targetCompanyId));
                        fetchInitialData();
                    } else {
                        setCompanyDevices([]);
                        // Update local company capacity if needed
                        if (localCompany) setLocalCompany({ ...localCompany, active_screens: 0 });
                        await fetchInitialData();
                    }
                    setAlertModalData({ title: "Éxito", message: "Todas las pantallas han sido desvinculadas.", type: "success" });
                } catch (e) {
                    setAlertModalData({ title: "Error", message: e.message, type: "error" });
                }
            }
        });
    };


    const saveAllChanges = async () => {
        try {
            const headers = { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` };
            const storedUser = JSON.parse(localStorage.getItem('user') || '{}');
            const targetId = impersonatingCompanyId || storedUser.company_id;

            // Prepare payload - EXPLICITLY filter for allowed fields only
            const allowedFields = [
                'name', 'layout_type', 'primary_color', 'secondary_color', 'accent_color',
                'logo_url', 'filler_keywords', 'google_drive_link', 'video_source', 'video_playlist',
                'sidebar_content', 'bottom_bar_content', 'design_settings', 'pause_duration',
                'priority_content_url', 'ad_frequency', 'rif', 'address', 'phone', 'whatsapp',
                'instagram', 'facebook', 'tiktok', 'sidebar_header_type', 'sidebar_header_value'
            ];

            const payload = {};
            allowedFields.forEach(f => {
                if (localCompany[f] !== undefined) {
                    payload[f] = localCompany[f];
                }
            });

            // Ensure JSON objects are ready for serialization
            ['sidebar_content', 'bottom_bar_content', 'design_settings'].forEach(field => {
                if (typeof payload[field] === 'string') {
                    try { payload[field] = JSON.parse(payload[field]); } catch (e) { }
                }
            });

            const res = await fetch(`${API_BASE}/companies/${targetId}`, {
                method: 'PATCH',
                headers,
                body: JSON.stringify(payload),
            });

            if (!res.ok) throw new Error("Failed to save");

            const data = await res.json();

            // Reparse response
            ['sidebar_content', 'bottom_bar_content', 'design_settings'].forEach(field => {
                if (data[field] && typeof data[field] === 'string') {
                    try { data[field] = JSON.parse(data[field]); } catch (e) { }
                }
            });

            setCompany(data);
            setLocalCompany(data);
            setUnsavedChanges(false);
            setAlertModalData({ title: "Guardado", message: "Cambios guardados correctamente", type: "success" });
        } catch (err) {
            console.error("Save Error:", err);
            setAlertModalData({ title: "Error", message: "Error al guardar: " + err.message, type: "error" });
        }
    };

    const handleLocalChange = (updates) => {
        setLocalCompany(prev => {
            const newState = { ...prev };
            for (const key in updates) {
                if (typeof updates[key] === 'object' && updates[key] !== null && !Array.isArray(updates[key])) {
                    // Handle case where previous value is a JSON string (common in DB)
                    let prevObj = newState[key];
                    if (typeof prevObj === 'string') {
                        try { prevObj = JSON.parse(prevObj); }
                        catch { prevObj = {}; }
                    }
                    newState[key] = { ...(prevObj || {}), ...updates[key] };
                } else {
                    newState[key] = updates[key];
                }
            }
            return newState;
        });
        setUnsavedChanges(true);
    };

    const handleImpersonate = async (targetCompany) => {
        setLoading(true);
        try {
            const headers = { 'Authorization': `Bearer ${token}` };
            const res = await fetch(`${API_BASE}/companies/${targetCompany.id}`, { headers });
            const fullComp = await res.json();
            setImpersonatingCompanyId(targetCompany.id);
            setCompany(fullComp);
            setLocalCompany(fullComp);
            setView('client');
        } catch (err) {
            console.error("Impersonation error", err);
            alert("Error al cargar datos de empresa");
        } finally {
            setLoading(false);
        }
    };

    const exitImpersonation = () => {
        setImpersonatingCompanyId(null);
        setView('superadmin');
        fetchInitialData();
    };

    const toggleStatus = async (id) => {
        try {
            const headers = { 'Authorization': `Bearer ${token}` };
            await fetch(`${API_BASE}/companies/${id}/toggle`, { method: 'POST', headers });
            fetchInitialData();
        } catch (err) {
            alert("Error al cambiar estado");
        }
    };

    const handlePingTV = async (deviceUuid) => {
        try {
            const res = await fetch(`${API_BASE}/diag/ping?uuid=${deviceUuid}`, {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (res.ok) {
                setAlertModalData({ title: "Ping Enviado", message: "La pantalla recibirá la señal de identificación en unos segundos.", type: "success" });
            } else {
                alert("Error al enviar ping");
            }
        } catch (e) {
            console.error("Ping Error", e);
        }
    };

    const deleteCompany = async (id, force = false) => {
        if (!force) {
            setConfirmModalData({
                title: "Eliminar Empresa",
                message: "¿Está seguro de eliminar esta empresa? Se perderán todos sus datos y dispositivos.",
                confirmText: "Eliminar",
                type: "danger",
                onConfirm: () => deleteCompany(id, true)
            });
            return;
        }
        try {
            const res = await fetch(`${API_BASE}/admin/companies/${id}`, {
                method: 'DELETE',
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (!res.ok) throw new Error("Error al eliminar");
            setCompanies(companies.filter(c => c.id !== id));
            setAlertModalData({ title: "Éxito", message: "Empresa eliminada", type: "success" });
        } catch (err) { setAlertModalData({ title: "Error", message: err.message, type: "error" }); }
    };

    const toggleCompanyStatus = async (company, force = false) => {
        if (!force) {
            const isSuspending = company.is_active;
            setConfirmModalData({
                title: isSuspending ? "Suspender Empresa" : "Reactivar Empresa",
                message: isSuspending
                    ? `¿Seguro que desea suspender a ${company.name}? Todas sus pantallas dejarán de transmitir inmediatamente.`
                    : `¿Desea reactivar el servicio para ${company.name}?`,
                confirmText: isSuspending ? "Suspender" : "Activar",
                type: isSuspending ? "danger" : "primary",
                onConfirm: () => toggleCompanyStatus(company, true)
            });
            return;
        }

        try {
            const res = await fetch(`${API_BASE}/companies/${company.id}/toggle`, {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${token}` }
            });

            if (!res.ok) throw new Error("Error al cambiar estado");

            setCompanies(companies.map(c => c.id === company.id ? { ...c, is_active: !c.is_active } : c));
            setAlertModalData({
                title: "Éxito",
                message: `Empresa ${company.is_active ? 'suspendida' : 'activada'} correctamente`,
                type: "success"
            });
        } catch (err) {
            setAlertModalData({ title: "Error", message: err.message, type: "error" });
        }
    };

    const deleteUser = async (id, force = false) => {
        if (!force) {
            setConfirmModalData({
                title: "Eliminar Usuario",
                message: "¿Seguro que deseas eliminar este usuario?",
                confirmText: "Eliminar",
                type: "danger",
                onConfirm: () => deleteUser(id, true)
            });
            return;
        }

        try {
            const res = await fetch(`${API_BASE}/admin/users/${id}`, {
                method: 'DELETE',
                headers: { 'Authorization': `Bearer ${token}` }
            });

            if (!res.ok) {
                const data = await res.json();
                throw new Error(data.detail || "Error al eliminar");
            }
            await fetchInitialData();
            setAlertModalData({ title: "Éxito", message: "Usuario eliminado", type: "success" });
        } catch (err) {
            console.error('deleteUser error:', err);
            setAlertModalData({ title: "Error", message: err.message, type: "error" });
        }
    };

    const saveCompany = async (companyData) => {
        try {
            const headers = { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` };
            const { username, password, ...rest } = companyData;
            let companyId = companyData.id;

            if (companyId) {
                const payload = { ...rest };
                if (!payload.valid_until) payload.valid_until = null;

                await fetch(`${API_BASE}/companies/${companyId}`, {
                    method: 'PATCH',
                    headers,
                    body: JSON.stringify(payload),
                });

                if (username || password) {
                    await fetch(`${API_BASE}/companies/${companyId}/credentials`, {
                        method: 'PATCH',
                        headers,
                        body: JSON.stringify({ username, password })
                    });
                }
            } else {
                const payload = { ...companyData };
                if (!payload.valid_until) payload.valid_until = null;

                // Ensure max_screens is integer
                payload.max_screens = parseInt(payload.max_screens) || 1;

                await fetch(`${API_BASE}/companies/`, {
                    method: 'POST',
                    headers,
                    body: JSON.stringify(payload),
                });
            }
            setShowCompanyModal(false);
            setSelectedCompany(null);
            fetchInitialData();
            setAlertModalData({ title: "Éxito", message: "Empresa guardada correctamente", type: "success" });
        } catch (err) {
            setAlertModalData({ title: "Error", message: "Error al guardar empresa: " + err.message, type: "error" });
        }
    };

    const saveAdminProfile = async (creds) => {
        try {
            const headers = { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` };
            const res = await fetch(`${API_BASE}/admin/me`, {
                method: 'PATCH',
                headers,
                body: JSON.stringify(creds)
            });
            if (!res.ok) {
                const errData = await res.json();
                throw new Error(errData.detail || "Error al actualizar perfil");
            }
            setAlertModalData({ title: "Éxito", message: "Perfil actualizado correctamente", type: "success" });
            setShowAdminPassModal(false);
        } catch (err) {
            setAlertModalData({ title: "Error", message: err.message, type: "error" });
        }
    };

    const savePayment = async (paymentData) => {
        try {
            const headers = { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` };
            await fetch(`${API_BASE}/admin/payments/create`, {
                method: 'POST',
                headers,
                body: JSON.stringify(paymentData),
            });
            setShowPaymentModal(false);
            fetchInitialData();
        } catch (err) {
            alert('Error');
        }
    };

    const viewDetails = async (comp) => {
        setSelectedCompany(comp);
        try {
            const headers = { 'Authorization': `Bearer ${token}` };
            const res = await fetch(`${API_BASE}/admin/companies/${comp.id}/devices`, { headers });
            const devs = await res.json();
            setCompanyDevices(devs);

            const pRes = await fetch(`${API_BASE}/admin/payments/${comp.id}`, { headers });
            const pData = await pRes.json();
            setDetailsPayments(pData);
            setShowDetailsModal(true);
        } catch (err) { console.error(err); }
    };

    const generateRegistrationCode = async (cid) => {
        console.log('generateRegistrationCode called with cid:', cid);
        console.log('Current state - company:', company, 'localCompany:', localCompany, 'impersonatingCompanyId:', impersonatingCompanyId);

        if (!cid) {
            alert('Error: ID de empresa no disponible');
            console.error('No company ID provided to generateRegistrationCode');
            return;
        }

        try {
            const headers = { 'Authorization': `Bearer ${token}` };
            console.log('Sending request to:', `${API_BASE}/devices/generate-code?company_id=${cid}`);
            const res = await fetch(`${API_BASE}/devices/generate-code?company_id=${cid}`, { method: 'POST', headers });
            const data = await res.json();
            console.log('Response Details:', JSON.stringify(data, null, 2));

            if (!res.ok) {
                console.error('Server returned error:', data);
                throw new Error(data.detail || JSON.stringify(data) || 'Error desconocido del servidor');
            }

            const tvUrl = window.location.origin.replace('8081', '8080'); // Ajuste temporal para dev
            const message = `¡CÓDIGO GENERADO CON ÉXITO!\n\nCÓDIGO: ${data.code}\nEXPIRA EN: ${data.expires_in_minutes} minutos\n\nInstrucciones:\n1. Ve a la TV\n2. Ingresa este código en la pantalla de registro`;

            // Reemplazado alert por modal visual
            setCodeModalData(data);

            // También intentar copiar al portapapeles
            try {
                await navigator.clipboard.writeText(data.code);
                console.log('Código copiado al portapapeles');
            } catch (e) { console.error('No se pudo copiar al portapapeles', e); }

        } catch (err) {
            console.error('CRITICAL Error generating code:', err);
            alert(`ERROR AL VINCULAR:\n${err.message}\n\nRevisa la consola para más detalles.`);
        }
    };
    const dashboardIsPermitted = (field) => {
        if (view === 'superadmin' || impersonatingCompanyId) return true;
        const perms = company?.client_editable_fields ? company.client_editable_fields.split(',') : [];
        return perms.includes(field);
    };

    const isSuperAdmin = view === 'superadmin' || impersonatingCompanyId !== null;

    const hasPermission = (section, action = 'view') => {
        return isAdmin || userRole === 'admin_master';
    };

    if (view === 'login') {
        return (
            <div className="login-screen">
                <div className="glass-card login-card">
                    <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
                        <img src="/venrides_logo.png" alt="VenridesScreenS" style={{ height: '360px', maxWidth: '100%', marginBottom: '0', filter: 'drop-shadow(0 4px 15px rgba(0,0,0,0.3))' }} />
                        <p style={{ opacity: 0.6, fontSize: '1.2rem', marginTop: '-20px' }}>Panel de Gestión</p>
                    </div>
                    <form onSubmit={handleLogin}>
                        <label>Correo Electrónico (Email)</label>
                        <input type="email" value={credentials.username} onChange={e => setCredentials({ ...credentials, username: e.target.value })} required placeholder="usuario@ejemplo.com" />
                        <label>Contraseña</label>
                        <input type="password" value={credentials.password} onChange={e => setCredentials({ ...credentials, password: e.target.value })} required />

                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '0.5rem', marginBottom: '1rem' }}>
                            <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', margin: 0 }}>
                                <input
                                    type="checkbox"
                                    checked={rememberMe}
                                    onChange={e => setRememberMe(e.target.checked)}
                                    style={{ width: 'auto', margin: 0 }}
                                />
                                <span style={{ fontSize: '0.85rem' }}>Recordarme</span>
                            </label>
                            <a
                                href="#"
                                onClick={(e) => { e.preventDefault(); setShowForgotPassword(true); }}
                                style={{ color: 'var(--primary-color)', fontSize: '0.85rem', textDecoration: 'none' }}
                            >
                                ¿Olvidaste tu contraseña?
                            </a>
                        </div>

                        <button type="submit" className="btn btn-primary" style={{ width: '100%' }} disabled={loading}>Entrar</button>
                    </form>
                </div>
                {/* GLOBAL REPLACEMENT MODALS */}
                {confirmModalData && <Modal isOpen={!!confirmModalData} onClose={() => setConfirmModalData(null)} title={confirmModalData.title || "Confirmación"}>
                    <div style={{ textAlign: 'center', padding: '1rem' }}>
                        <p style={{ fontSize: '1.1rem', marginBottom: '1.5rem', color: 'var(--text-main)' }}>{confirmModalData.message}</p>
                        <div style={{ display: 'flex', gap: '1rem', justifyContent: 'center' }}>
                            <button onClick={() => setConfirmModalData(null)} className="btn btn-secondary" style={{ flex: 1 }}>{confirmModalData.cancelText || "Cancelar"}</button>
                            <button onClick={() => { if (confirmModalData.onConfirm) confirmModalData.onConfirm(); setConfirmModalData(null); }} className={`btn btn-${confirmModalData.type === 'danger' ? 'danger' : 'primary'}`} style={{ flex: 1 }}>{confirmModalData.confirmText || "Confirmar"}</button>
                        </div>
                    </div>
                </Modal>}
                {alertModalData && <Modal isOpen={!!alertModalData} onClose={() => setAlertModalData(null)} title={alertModalData.title || "Aviso"}>
                    <div style={{ textAlign: 'center', padding: '1rem' }}>
                        <div style={{ marginBottom: '1rem' }}>{alertModalData.type === 'error' ? <XCircle size={40} color="var(--error)" /> : <CheckCircle size={40} color="var(--success)" />}</div>
                        <p style={{ fontSize: '1.1rem', marginBottom: '1.5rem', color: 'var(--text-main)' }}>{alertModalData.message}</p>
                        <button onClick={() => setAlertModalData(null)} className="btn btn-primary" style={{ width: '100%' }}>Aceptar</button>
                    </div>
                </Modal>}
            </div>
        );
    }

    if (view === 'superadmin') {
        const groups = [
            {
                title: "Administración",
                items: [
                    { id: 'companies', label: 'Empresas', icon: <Building size={18} />, perm: 'companies' },
                    { id: 'users', label: 'Usuarios', icon: <Users size={18} />, perm: 'users' },
                    { id: 'devices', label: 'Dispositivos', icon: <Monitor size={18} />, perm: 'devices' },
                    { id: 'payments', label: 'Pagos', icon: <DollarSign size={18} />, perm: 'payments' },
                ]
            },
            {
                title: "CRM & Marketing",
                items: [
                    { id: 'ecosystem', label: 'Ecosistema', icon: <Activity size={18} /> },
                    { id: 'crm', label: 'CRM & Auto', icon: <Mail size={18} /> },
                    { id: 'sales', label: 'Ventas', icon: <ShoppingCart size={18} /> },
                ]
            },
            {
                title: "Inteligencia",
                items: [
                    { id: 'seo', label: 'SEO & Analytics', icon: <BarChart size={18} /> },
                ]
            },
            {
                title: "Soporte",
                items: [
                    { id: 'helpdesk', label: 'Tickets', icon: <LifeBuoy size={18} />, badge: supportUnreadCount },
                    { id: 'chat', label: 'Chat Interno', icon: <MessageSquare size={18} /> },
                ]
            },
            {
                title: "Configuración",
                items: [
                    { id: 'global_ad', label: 'Publicidad Global', icon: <Bell size={18} />, perm: 'global_ad' },
                    { id: 'stats', label: 'Estadísticas', icon: <Layout size={18} />, perm: 'stats' },
                ]
            }
        ];

        return (
            <div className="admin-dashboard-layout">
                <GlobalStyles />
                <aside className="admin-sidebar">
                    <div className="sidebar-header-custom">
                        <img src="/venrides_logo.png" alt="Logo" style={{ height: '60px', marginBottom: '0.5rem' }} />
                        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                            <div style={{ fontWeight: '900', fontSize: '1.2rem', color: 'var(--primary-color)', lineHeight: 1, letterSpacing: '0.1rem' }}>MASTER</div>
                            <div style={{ fontSize: '0.6rem', opacity: 0.5, fontWeight: 'bold', textTransform: 'uppercase', marginTop: '0.2rem' }}>Network Control Center</div>
                        </div>
                    </div>
                    <div className="sidebar-content-custom">
                        {groups.map(group => (
                            <div key={group.title} className="sidebar-group-custom">
                                <div className="sidebar-group-title-custom">{group.title}</div>
                                {group.items.map(item => {
                                    if (item.perm && !hasPermission(item.perm)) return null;
                                    return (
                                        <button
                                            key={item.id}
                                            className={`sidebar-item-custom ${adminTab === item.id ? 'active' : ''}`}
                                            onClick={() => setAdminTab(item.id)}
                                        >
                                            {item.icon}
                                            <span style={{ flex: 1 }}>{item.label}</span>
                                            {item.badge > 0 && <span className="sidebar-badge-custom">{item.badge}</span>}
                                        </button>
                                    );
                                })}
                            </div>
                        ))}
                    </div>
                    <div className="sidebar-footer-custom">
                        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', padding: '0.5rem' }}>
                            <ThemeSwitch theme={theme} toggle={toggleTheme} />
                            <div style={{ flex: 1 }}></div>
                            <button onClick={() => setShowAdminPassModal(true)} className="btn" title="Perfil" style={{ padding: '0.5rem' }}><Key size={18} /></button>
                            <button onClick={handleLogout} className="btn" style={{ padding: '0.5rem', color: '#f43f5e' }} title="Salir"><LogOut size={18} /></button>
                        </div>
                    </div>
                </aside>

                <main className="admin-main-content">
                    <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2rem' }}>
                        <div style={{ textTransform: 'uppercase', fontSize: '0.75rem', fontWeight: 'bold', opacity: 0.5, letterSpacing: '0.1rem' }}>
                            Venrides / {adminTab.replace('_', ' ')}
                        </div>
                        {bcvRate && (
                            <div className="glass-card" style={{ padding: '0.4rem 1rem', fontSize: '0.8rem', fontWeight: 'bold', display: 'flex', alignItems: 'center', gap: '0.5rem', border: '1px solid var(--primary-color)' }}>
                                <span style={{ opacity: 0.6 }}>BCV:</span> {bcvRate} Bs.
                            </div>
                        )}
                    </header>

                    {adminTab === 'helpdesk' && <Helpdesk token={token} userRole={userRole} />}

                    {adminTab === 'companies' && !showCompanyForm && (
                        <div className="glass-card">
                            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '1.5rem', alignItems: 'center' }}>
                                <div>
                                    <h1 style={{ fontSize: '1.4rem', fontWeight: 'bold', color: 'var(--primary-color)' }}>Empresas Registradas</h1>
                                    <p style={{ fontSize: '0.8rem', opacity: 0.6 }}>Gestione los clientes y sus planes activos</p>
                                </div>
                                {hasPermission('companies', 'create') && (
                                    <button className="btn btn-primary" style={{ padding: '0.7rem 1.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }} onClick={() => { setSelectedCompany(null); setShowCompanyForm(true); }}><Plus size={20} /> Nueva Empresa</button>
                                )}
                            </div>
                            <div className="table-responsive">
                                <table className="admin-table">
                                    <thead><tr><th>Empresa</th><th>Plan</th><th>Screens</th><th>Estado</th><th>Vencimiento</th><th>Acciones</th></tr></thead>
                                    <tbody>
                                        {companies.map(c => (
                                            <tr key={c.id}>
                                                <td style={{ fontWeight: '600' }}>{c.name}</td>
                                                <td style={{ textTransform: 'uppercase', fontSize: '0.8rem' }}>{c.plan}</td>
                                                <td><span className="badge-screens">{c.total_screens} / {c.max_screens} TV</span></td>
                                                <td>
                                                    <span className={`badge-status ${c.is_active ? 'active' : 'inactive'}`}>
                                                        {c.is_active ? '✓ Activo' : '✗ Suspendido'}
                                                    </span>
                                                </td>
                                                <td style={{ fontSize: '0.8rem' }}>{c.valid_until ? new Date(c.valid_until).toLocaleDateString() : 'N/A'}</td>
                                                <td style={{ display: 'flex', justifyContent: 'flex-end' }}>
                                                    <div className="action-buttons">
                                                        <Tooltip text="Editar Configuración"><button onClick={() => { setSelectedCompany(c); setShowCompanyForm(true); }} className="action-btn edit"><Edit size={16} /></button></Tooltip>
                                                        <Tooltip text="Gestionar Contenido TV"><button onClick={() => handleImpersonate(c)} className="action-btn impersonate"><Monitor size={16} /></button></Tooltip>
                                                        <Tooltip text={c.is_active ? "Suspender Servicio" : "Reactivar Servicio"}>
                                                            <button onClick={() => toggleCompanyStatus(c)} className={`action-btn ${c.is_active ? 'suspend' : 'activate'}`} style={{ color: c.is_active ? 'var(--error)' : 'var(--success)' }}>
                                                                <Power size={16} />
                                                            </button>
                                                        </Tooltip>
                                                        <Tooltip text="Estadísticas / Detalles"><button onClick={() => viewDetails(c)} className="action-btn view"><Eye size={16} /></button></Tooltip>
                                                        <Tooltip text="Eliminar Empresa"><button onClick={() => deleteCompany(c.id)} className="action-btn suspend"><Trash2 size={16} /></button></Tooltip>
                                                    </div>
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}

                    {adminTab === 'companies' && showCompanyForm && (
                        <div className="full-page-form">
                            <div className="form-container">
                                <CompanyForm
                                    onGenerateCode={generateRegistrationCode}
                                    company={selectedCompany}
                                    isSuperAdmin={true}
                                    activeUsers={users.filter(u => u.company_id === selectedCompany?.id)}
                                    activeDevices={allDevices.filter(d => d.company_id === selectedCompany?.id)}
                                    onSave={async (data) => {
                                        await saveCompany(data);
                                        setShowCompanyForm(false);
                                    }}
                                    onCancel={() => setShowCompanyForm(false)}
                                    onChange={(data) => setLocalCompany(data)}
                                />
                            </div>
                        </div>
                    )}

                    {adminTab === 'users' && (
                        <div className="glass-card">
                            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '1.5rem', alignItems: 'center' }}>
                                <h2 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: '0.5rem' }}><Users size={20} /> Gestión de Usuarios</h2>
                                {isMaster && (
                                    <button className="btn btn-primary" onClick={() => setShowUserModal(true)} style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                                        <Plus size={18} /> Crear Usuario
                                    </button>
                                )}
                            </div>
                            <div className="table-responsive">
                                <table className="admin-table">
                                    <thead><tr><th>Usuario</th><th>Empresa</th><th>Rol</th><th>Estatus</th><th>Acciones</th></tr></thead>
                                    <tbody>
                                        {users.map(u => (
                                            <tr key={u.id}>
                                                <td style={{ fontWeight: '600' }}>{u.username}</td>
                                                <td>{companies.find(c => c.id === u.company_id)?.name || 'N/A'}</td>
                                                <td>
                                                    <span className={`badge-role ${u.role}`}>
                                                        {u.role === 'admin_master' && 'Super Admin'}
                                                        {u.role === 'admin_empresa' && 'Admin Empresa'}
                                                        {u.role === 'operador_empresa' && 'Operador Empresa'}
                                                    </span>
                                                </td>
                                                <td>
                                                    <span className={`badge-status ${u.is_active !== false ? 'active' : 'inactive'}`}>
                                                        {u.is_active !== false ? 'Activo' : 'Inactivo'}
                                                    </span>
                                                </td>
                                                <td style={{ display: 'flex', gap: '5px' }}>
                                                    <Tooltip text="Editar Usuario">
                                                        <button onClick={() => {
                                                            setEditingUser(u);
                                                            setShowUserModal(true);
                                                        }} className="action-btn edit">
                                                            <Edit size={16} />
                                                        </button>
                                                    </Tooltip>
                                                    <Tooltip text={u.is_active !== false ? "Suspender Usuario" : "Activar Usuario"}>
                                                        <button onClick={async () => {
                                                            try {
                                                                const newStatus = u.is_active === false;
                                                                const res = await fetch(`${API_BASE}/admin/users/${u.id}/status?is_active=${newStatus}`, {
                                                                    method: 'PATCH',
                                                                    headers: { 'Authorization': `Bearer ${token}` }
                                                                });
                                                                if (res.ok) fetchInitialData();
                                                                else alert("Error al cambiar estado");
                                                            } catch (e) { alert("Error"); }
                                                        }} className={`action-btn ${u.is_active !== false ? 'suspend' : 'activate'}`}>
                                                            {u.is_active !== false ? <XCircle size={16} /> : <CheckCircle size={16} />}
                                                        </button>
                                                    </Tooltip>
                                                    <Tooltip text="Eliminar Usuario">
                                                        <button onClick={() => deleteUser(u.id)} className="action-btn delete"><Trash2 size={16} /></button>
                                                    </Tooltip>
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}

                    {adminTab === 'devices' && (
                        <div className="glass-card">
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
                                <h2 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: '0.5rem' }}><Monitor size={20} /> Gestión de Dispositivos</h2>
                            </div>

                            {allDevices.length === 0 ? (
                                <div style={{ textAlign: 'center', padding: '2rem', opacity: 0.6 }}>
                                    <Monitor size={48} style={{ marginBottom: '1rem', opacity: 0.5 }} />
                                    <p>No se encontraron pantallas vinculadas.</p>
                                </div>
                            ) : (
                                Object.entries(allDevices.reduce((acc, d) => {
                                    const cName = d.company_name || companies.find(c => c.id === d.company_id)?.name || 'Sin Asignar';
                                    if (!acc[cName]) acc[cName] = [];
                                    acc[cName].push(d);
                                    return acc;
                                }, {})).map(([compName, devs]) => (
                                    <div key={compName} className="company-group" style={{ marginBottom: '2rem' }}>
                                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.8rem', borderBottom: '1px solid rgba(255,255,255,0.1)', paddingBottom: '0.5rem' }}>
                                            <Building size={16} color="var(--primary-color)" />
                                            <h3 style={{ fontSize: '1rem', flex: 1, margin: 0, color: '#f3f4f6' }}>{compName} <span style={{ fontSize: '0.7rem', opacity: 0.6, background: 'rgba(255,255,255,0.1)', padding: '2px 6px', borderRadius: '4px', marginLeft: '0.5rem' }}>{devs.length} Pantallas</span></h3>
                                            <button
                                                onClick={() => generateRegistrationCode(devs[0]?.company_id)}
                                                style={{ background: 'var(--primary-color)', border: 'none', borderRadius: '4px', color: 'white', padding: '0.2rem 0.5rem', cursor: 'pointer', fontSize: '0.7rem', display: 'flex', alignItems: 'center', gap: '0.2rem' }}
                                            >
                                                <Monitor size={12} /> Vincular
                                            </button>
                                        </div>
                                        <div className="table-responsive">
                                            <table className="admin-table">
                                                <thead><tr><th>Nombre</th><th>Empresa</th><th>UUID</th><th>Estado</th><th>Acciones</th></tr></thead>
                                                <tbody>
                                                    {devs.map(d => (
                                                        <tr key={d.id}>
                                                            <td>
                                                                <div style={{ fontWeight: 'bold' }}>{d.name}</div>
                                                            </td>
                                                            <td style={{ fontSize: '0.85rem', opacity: 0.7 }}>{compName}</td>
                                                            <td style={{ fontSize: '0.7rem', opacity: 0.5, fontFamily: 'monospace' }}>{d.uuid}</td>
                                                            <td>
                                                                <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                                                                    <span className={`badge-status ${d.is_online ? 'active' : 'inactive'}`} style={{ fontSize: '0.7rem' }}>
                                                                        {d.is_online ? '● Online' : '○ Offline'}
                                                                    </span>
                                                                    <span className={`badge-status ${d.is_active ? 'active' : 'inactive'}`} style={{ background: d.is_active ? 'rgba(16, 185, 129, 0.1)' : 'rgba(244, 63, 94, 0.1)', color: d.is_active ? '#10b981' : '#f43f5e', fontSize: '0.7rem' }}>
                                                                        {d.is_active ? 'HABILITADO' : 'SUSPENDIDO'}
                                                                    </span>
                                                                </div>
                                                            </td>
                                                            <td>
                                                                <div className="action-buttons">
                                                                    <Tooltip text={d.is_active ? "Suspender Pantalla" : "Reactivar Pantalla"}>
                                                                        <button
                                                                            onClick={() => toggleDeviceStatus(d)}
                                                                            className={`action-btn ${d.is_active ? 'suspend' : 'activate'}`}
                                                                        >
                                                                            {d.is_active ? <XCircle size={16} /> : <CheckCircle size={16} />}
                                                                        </button>
                                                                    </Tooltip>
                                                                    <Tooltip text="Identificar Pantalla (Ping)">
                                                                        <button onClick={() => handlePingTV(d.uuid)} className="action-btn" style={{ color: '#fbbf24', background: 'rgba(251, 191, 36, 0.1)' }}>
                                                                            <Wifi size={16} />
                                                                        </button>
                                                                    </Tooltip>
                                                                    <Tooltip text="Renombrar / Editar">
                                                                        <button onClick={() => handleRenameClick(d)} className="action-btn edit"><Edit size={16} /></button>
                                                                    </Tooltip>
                                                                    <Tooltip text="Eliminar Dispositivo">
                                                                        <button onClick={() => deleteDevice(d.uuid)} className="action-btn delete"><Trash2 size={16} /></button>
                                                                    </Tooltip>
                                                                </div>
                                                            </td>
                                                        </tr>
                                                    ))}
                                                </tbody>
                                            </table>
                                        </div>
                                    </div>
                                ))
                            )}
                        </div>
                    )}

                    {adminTab === 'payments' && (
                        <div className="glass-card">
                            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '1.5rem', alignItems: 'center' }}>
                                <h2 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}><DollarSign size={20} /> Historial de Pagos</h2>
                                <button className="btn btn-primary" onClick={() => setShowPaymentModal(true)}><Plus size={18} /> Registrar Pago</button>
                            </div>
                            <div className="table-responsive">
                                <table className="admin-table">
                                    <thead><tr><th>Fecha</th><th>Empresa</th><th>Monto</th><th>Método</th><th>Acciones</th></tr></thead>
                                    <tbody>
                                        {payments.map(p => (
                                            <tr key={p.id}>
                                                <td>{new Date(p.payment_date).toLocaleDateString()}</td>
                                                <td style={{ fontWeight: '500' }}>{companies.find(c => c.id === p.company_id)?.name || p.company_id}</td>
                                                <td style={{ color: '#10b981', fontWeight: 'bold' }}>{p.currency} {p.amount}</td>
                                                <td style={{ fontSize: '0.8rem', opacity: 0.7 }}>{p.payment_method}</td>
                                                <td>
                                                    <button onClick={() => deletePayment(p.id)} className="action-btn suspend" title="Eliminar Pago"><Trash2 size={16} /></button>
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}
                    {adminTab === 'global_ad' && (
                        <div className="glass-card">
                            <h2 style={{ marginBottom: '1.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}><Bell size={20} /> Publicidad Global</h2>
                            <MasterAdManager token={token} />
                        </div>
                    )}

                    {adminTab === 'ecosystem' && (
                        <div className="glass-card">
                            <h2 style={{ marginBottom: '1.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}><Activity size={20} /> Estatus del Ecosistema Venrides</h2>
                            <EcosystemDashboard token={token} />
                        </div>
                    )}

                    {adminTab === 'crm' && (
                        <div className="glass-card">
                            <h2 style={{ marginBottom: '1.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}><Calendar size={20} /> CRM: Automatización y Calendario</h2>
                            <CrmPanel token={token} />
                        </div>
                    )}

                    {adminTab === 'sales' && (
                        <div className="glass-card">
                            <h2 style={{ marginBottom: '1.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}><ShoppingCart size={20} /> Ventas: Marketing y Afiliados</h2>
                            <SalesPanel token={token} />
                        </div>
                    )}

                    {adminTab === 'stats' && (
                        <div className="glass-card">
                            <h2>Estadísticas Generales</h2>
                            {stats && (
                                <div className="stats-grid" style={{ marginTop: '1rem' }}>
                                    <div className="stat-card"><div className="value">{stats.total_companies}</div><div className="label">Empresas</div></div>
                                    <div className="stat-card"><div className="value">{stats.total_screens}</div><div className="label">Pantallas</div></div>
                                    <div className="stat-card"><div className="value">${stats.monthly_revenue}</div><div className="label">Este Mes</div></div>
                                </div>
                            )}
                        </div>
                    )}

                    {adminTab === 'chat' && (
                        <div className="glass-card">
                            <h2 style={{ marginBottom: '1.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}><MessageSquare size={20} /> Chat Interno</h2>
                            <ChatPanel token={token} currentUser={safeParse(localStorage.getItem('user'), {})} />
                        </div>
                    )}

                    {adminTab === 'seo' && (
                        <div className="glass-card">
                            <h2 style={{ marginBottom: '1.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}><BarChart size={20} /> SEO & Analítica de Landing</h2>
                            <SeoPanel token={token} />
                        </div>
                    )}

                    <Modal isOpen={showAdminPassModal} onClose={() => setShowAdminPassModal(false)} title="Mi Perfil Master">
                        <AdminProfileForm onSave={saveAdminProfile} onCancel={() => setShowAdminPassModal(false)} />
                    </Modal>
                    <Modal isOpen={showCompanyModal} onClose={() => setShowCompanyModal(false)} title={selectedCompany ? 'Editar' : 'Nueva'}>
                        <CompanyForm company={selectedCompany} onSave={saveCompany} onCancel={() => setShowCompanyModal(false)} isSuperAdmin={true} onGenerateCode={generateRegistrationCode} />
                    </Modal>
                    <Modal isOpen={showPaymentModal} onClose={() => setShowPaymentModal(false)} title="Nuevo Pago">
                        <PaymentForm companies={companies} onSave={savePayment} onCancel={() => setShowPaymentModal(false)} />
                    </Modal>
                    <Modal isOpen={showUserModal} onClose={() => { setShowUserModal(false); setEditingUser(null); }} title={editingUser ? "Editar Usuario" : "Crear Nuevo Usuario"}>
                        <UserForm
                            companies={companies}
                            initialData={editingUser}
                            onSave={async (u) => {
                                const url = editingUser
                                    ? `${API_BASE}/admin/users/${editingUser.id}`
                                    : `${API_BASE}/admin/users/`;
                                const method = editingUser ? 'PATCH' : 'POST';

                                const res = await fetch(url, {
                                    method,
                                    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
                                    body: JSON.stringify(u)
                                });
                                if (res.ok) {
                                    alert(editingUser ? "Usuario actualizado" : "Usuario creado");
                                    setShowUserModal(false);
                                    setEditingUser(null);
                                    fetchInitialData();
                                } else {
                                    const err = await res.json();
                                    alert("Error: " + (err.detail || "No se pudo guardar"));
                                }
                            }}
                            onCancel={() => { setShowUserModal(false); setEditingUser(null); }}
                        />
                    </Modal>
                    <Modal isOpen={showDetailsModal} onClose={() => setShowDetailsModal(false)} title="Detalles Empresa">
                        {selectedCompany && (
                            <div>
                                <h3>Dispositivos ({companyDevices.length}/{selectedCompany.max_screens})</h3>
                                <ul>{companyDevices.map(d => <li key={d.id}>{d.name}</li>)}</ul>
                            </div>
                        )}
                    </Modal>

                    <Modal isOpen={!!codeModalData} onClose={() => setCodeModalData(null)} title="Vincular Nueva Pantalla">
                        {codeModalData && (
                            <div style={{ textAlign: 'center', padding: '1rem' }}>
                                <div style={{ marginBottom: '1rem' }}>
                                    <Monitor size={48} color="var(--primary-color)" style={{ opacity: 0.8 }} />
                                </div>
                                <h3 style={{ margin: '0 0 1rem 0' }}>Código de Vinculación</h3>
                                <p style={{ opacity: 0.7, marginBottom: '0.5rem' }}>Ingresa el siguiente código en tu TV:</p>

                                <div style={{
                                    background: 'rgba(0,0,0,0.3)',
                                    padding: '1.5rem',
                                    borderRadius: '16px',
                                    marginBottom: '1.5rem',
                                    border: '2px dashed var(--primary-color)',
                                    display: 'inline-block',
                                    minWidth: '280px'
                                }}>
                                    <div style={{
                                        fontSize: '3.5rem',
                                        fontWeight: 'bold',
                                        letterSpacing: '8px',
                                        color: '#10b981',
                                        fontFamily: 'monospace',
                                        lineHeight: 1
                                    }}>
                                        {codeModalData.code}
                                    </div>
                                </div>

                                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', alignItems: 'center', opacity: 0.6, fontSize: '0.9rem' }}>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                        <Clock size={16} /> Expira en {codeModalData.expires_in_minutes} minutos
                                    </div>
                                    <div>El código fue copiado al portapapeles</div>
                                </div>

                                <button onClick={() => setCodeModalData(null)} className="btn btn-primary" style={{ width: '100%', marginTop: '2rem', justifyContent: 'center', padding: '1rem', fontSize: '1.1rem' }}>
                                    Entendido
                                </button>
                            </div>
                        )}
                    </Modal>
                    {/* GLOBAL REPLACEMENT MODALS */}
                    {confirmModalData && <Modal isOpen={!!confirmModalData} onClose={() => setConfirmModalData(null)} title={confirmModalData.title || "Confirmación"}>
                        <div style={{ textAlign: 'center', padding: '1rem' }}>
                            <p style={{ fontSize: '1.1rem', marginBottom: '1.5rem', color: 'var(--text-main)' }}>{confirmModalData.message}</p>
                            <div style={{ display: 'flex', gap: '1rem', justifyContent: 'center' }}>
                                <button onClick={() => setConfirmModalData(null)} className="btn btn-secondary" style={{ flex: 1 }}>{confirmModalData.cancelText || "Cancelar"}</button>
                                <button onClick={() => { if (confirmModalData.onConfirm) confirmModalData.onConfirm(); setConfirmModalData(null); }} className={`btn btn-${confirmModalData.type === 'danger' ? 'danger' : 'primary'}`} style={{ flex: 1 }}>{confirmModalData.confirmText || "Confirmar"}</button>
                            </div>
                        </div>
                    </Modal>}
                    {alertModalData && <Modal isOpen={!!alertModalData} onClose={() => setAlertModalData(null)} title={alertModalData.title || "Aviso"}>
                        <div style={{ textAlign: 'center', padding: '1rem' }}>
                            <div style={{ marginBottom: '1rem' }}>{alertModalData.type === 'error' ? <XCircle size={40} color="var(--error)" /> : <CheckCircle size={40} color="var(--success)" />}</div>
                            <p style={{ fontSize: '1.1rem', marginBottom: '1.5rem', color: 'var(--text-main)' }}>{alertModalData.message}</p>
                            <button onClick={() => setAlertModalData(null)} className="btn btn-primary" style={{ width: '100%' }}>Aceptar</button>
                        </div>
                    </Modal>}
                    <Modal isOpen={!!editingDevice} onClose={() => setEditingDevice(null)} title="Renombrar Dispositivo">
                        <div style={{ padding: '1rem' }}>
                            <label style={{ display: 'block', marginBottom: '0.5rem' }}>Nuevo Nombre</label>
                            <input
                                type="text"
                                value={renameDeviceName}
                                onChange={e => setRenameDeviceName(e.target.value)}
                                className="form-control"
                                style={{ width: '100%', padding: '0.8rem', marginBottom: '1.5rem', background: 'rgba(255,255,255,0.05)', color: '#fff', border: '1px solid rgba(255,255,255,0.1)' }}
                                autoFocus
                            />
                            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '1rem' }}>
                                <button onClick={() => setEditingDevice(null)} className="btn btn-secondary">Cancelar</button>
                                <button onClick={handleRenameSubmit} className="btn btn-primary">Guardar Cambios</button>
                            </div>
                        </div>
                    </Modal>
                </main>
            </div>
        );
    }

    if (view === 'operator') {
        return <OperatorView company={localCompany || company} token={token} onLogout={handleLogout} />;
    }

    if (view === 'client' && !company) {
        return (
            <div className="loading" style={{ flexDirection: 'column', gap: '1rem' }}>
                <div>Cargando datos de empresa...</div>
                <button onClick={handleLogout} className="btn" style={{ marginTop: '1rem', background: 'white', color: 'black', padding: '0.6rem 1.2rem', borderRadius: '8px', zIndex: 1000 }}>Cerrar Sesión</button>
            </div>
        );
    }

    // CLIENT VIEW
    return (
        <div className="dashboard-container">
            <GlobalStyles />
            <header className="dash-header">
                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                    <img src="/venrides_logo.png" alt="Venrides" className="app-logo" style={{ height: '125px' }} />
                    <div>
                        <h1 style={{ fontSize: '1.4rem', margin: 0 }}>VenrideScreenS</h1>
                        <p style={{ opacity: 0.6, fontSize: '0.8rem', margin: 0 }}>{localCompany?.name} | Panel de Control</p>
                    </div>
                </div>
                <div style={{ display: 'flex', gap: '0.8rem', alignItems: 'center' }}>
                    <ThemeSwitch theme={theme} toggle={toggleTheme} />
                    {unsavedChanges && (
                        <button onClick={saveAllChanges} className="btn btn-primary" style={{ animation: 'pulse 2s infinite', boxShadow: '0 0 15px rgba(16, 185, 129, 0.4)' }}>
                            <Check size={18} /> Guardar
                        </button>
                    )}
                    {impersonatingCompanyId ? (
                        <button onClick={exitImpersonation} className="btn" style={{ background: '#f59e0b', color: '#000', fontWeight: 'bold' }}>Volver Master</button>
                    ) : (
                        <button onClick={handleLogout} className="btn" style={{ background: 'rgba(244, 63, 94, 0.1)', color: '#f43f5e' }}><LogOut size={18} /></button>
                    )}
                </div>
            </header>

            <div className="grid-2" style={{ gridTemplateColumns: 'minmax(0, 1.2fr) minmax(0, 0.8fr)', alignItems: 'start' }}>
                {/* EDITOR SIDE */}
                <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', minHeight: '70vh', borderTop: '4px solid var(--primary-color)' }}>
                    <div className="tabs-navigation" style={{ display: 'flex', gap: '5px', marginBottom: '1.5rem', borderBottom: '1px solid var(--border-color)', paddingBottom: '0.5rem', overflowX: 'auto' }}>
                        {[
                            { id: 'profile', icon: Building, label: 'Perfil' },
                            // { id: 'management', icon: HardDrive, label: 'Menú' } REMOVED
                            { id: 'sidebar_tab', icon: Layout, label: 'Barra Lateral' },
                            { id: 'bottombar_tab', icon: MessageSquare, label: 'Barra Inferior' },
                            { id: 'videos', icon: PlaySquare, label: 'Videos' },
                            { id: 'messaging', icon: Mail, label: 'Mensajería' },
                            { id: 'users', icon: Users, label: 'Usuarios' },
                            { id: 'helpdesk', icon: LifeBuoy, label: 'Soporte', badge: supportUnreadCount }
                        ].filter(tab => {
                            if (tab.id === 'users' && (localCompany?.plan === 'free' || userRole === 'user_basic')) return false;
                            return true;
                        }).map(tab => (
                            <button
                                key={tab.id}
                                onClick={() => setClientTab(tab.id)}
                                className={`btn ${clientTab === tab.id ? 'btn-primary' : ''}`}
                                style={{ flex: 1, fontSize: '0.7rem', whiteSpace: 'nowrap', padding: '0.6rem 0.3rem', position: 'relative' }}
                            >
                                <tab.icon size={14} /> {tab.label}
                                {tab.badge > 0 && (
                                    <span style={{
                                        position: 'absolute',
                                        top: '2px',
                                        right: '2px',
                                        background: '#f43f5e',
                                        color: 'white',
                                        borderRadius: '50%',
                                        width: '16px',
                                        height: '16px',
                                        fontSize: '0.65rem',
                                        display: 'flex',
                                        alignItems: 'center',
                                        justifyContent: 'center',
                                        fontWeight: 'bold',
                                        border: '2px solid var(--card-bg)',
                                        boxShadow: '0 0 5px rgba(244, 63, 94, 0.5)'
                                    }}>
                                        {tab.badge}
                                    </span>
                                )}
                            </button>
                        ))}
                    </div>

                    <div className="tab-content" style={{ flex: 1 }}>
                        {clientTab === 'profile' && (() => {
                            const isEditable = (f) => isAdmin || (localCompany?.client_editable_fields || "").split(",").includes(f);

                            return (
                                <div className="company-form-full">
                                    <div className="form-sections-grid" style={{ gridTemplateColumns: '1fr' }}>
                                        <div className="form-section">
                                            <div className="section-title"><Building size={20} /> Información de Negocio</div>
                                            <div className="section-fields">
                                                <div className="field-group">
                                                    <label>Nombre Comercial</label>
                                                    <input value={localCompany?.name || ''} onChange={e => handleLocalChange({ name: e.target.value })} disabled={!isEditable('name')} />
                                                </div>
                                                <div className="field-group">
                                                    <label>RIF / Documento</label>
                                                    <input value={localCompany?.rif || ''} onChange={e => handleLocalChange({ rif: e.target.value })} disabled={!isEditable('rif')} />
                                                </div>
                                                <div className="field-group">
                                                    <label>Teléfono / WhatsApp</label>
                                                    <input value={localCompany?.phone || ''} onChange={e => handleLocalChange({ phone: e.target.value })} disabled={!isEditable('phone')} />
                                                </div>
                                                <div className="field-group">
                                                    <label>Email de Contacto</label>
                                                    <input value={localCompany?.email || ''} onChange={e => handleLocalChange({ email: e.target.value })} disabled={!isEditable('email')} />
                                                </div>
                                                <div className="field-group">
                                                    <label>WhatsApp (Link o Número)</label>
                                                    <input value={localCompany?.whatsapp || ''} onChange={e => handleLocalChange({ whatsapp: e.target.value })} disabled={!isEditable('whatsapp')} placeholder="+58412..." />
                                                </div>
                                                <div className="field-group">
                                                    <label>Instagram (@usuario)</label>
                                                    <input value={localCompany?.instagram || ''} onChange={e => handleLocalChange({ instagram: e.target.value })} disabled={!isEditable('instagram')} placeholder="@comercio" />
                                                </div>
                                                <div className="field-group">
                                                    <label>Facebook / Otros</label>
                                                    <input value={localCompany?.facebook || ''} onChange={e => handleLocalChange({ facebook: e.target.value })} disabled={!isEditable('facebook')} />
                                                </div>
                                                <div className="field-group">
                                                    <label>TikTok</label>
                                                    <input value={localCompany?.tiktok || ''} onChange={e => handleLocalChange({ tiktok: e.target.value })} disabled={!isEditable('tiktok')} />
                                                </div>
                                                <div className="field-group full">
                                                    <label>Dirección Física</label>
                                                    <textarea value={localCompany?.address || ''} onChange={e => handleLocalChange({ address: e.target.value })} rows={2} disabled={!isEditable('address')}></textarea>
                                                </div>
                                            </div>
                                        </div>

                                        <div className="form-section" style={{ marginTop: '2rem', borderTop: '1px solid var(--border-color)', paddingTop: '2rem' }}>
                                            <div className="section-title"><Monitor size={20} /> Gestión de Pantallas (TVs)</div>
                                            <div className="grid-2">
                                                <div className="glass-card" style={{ background: 'var(--bg-app)', padding: '1.2rem', border: '1px solid var(--border-color)' }}>
                                                    <label style={{ color: 'var(--text-secondary)' }}>Estatus del Plan</label>
                                                    <div style={{ fontWeight: 'bold', textTransform: 'uppercase', color: 'var(--accent-color)', fontSize: '1.4rem' }}>{localCompany?.plan} Plan</div>
                                                    <div style={{ fontSize: '0.8rem', opacity: 0.8, color: 'var(--text-main)', marginTop: '0.5rem' }}>
                                                        Capacidad: <strong>{companyDevices.length} / {localCompany?.max_screens}</strong> TVs en uso.
                                                    </div>
                                                </div>
                                                <div className="glass-card" style={{ background: 'var(--bg-app)', padding: '1.2rem', border: '1px solid var(--border-color)', display: 'flex', alignItems: 'center' }}>
                                                    <button
                                                        onClick={() => {
                                                            const companyId = impersonatingCompanyId || company?.id || localCompany?.id;
                                                            console.log('Vincular button clicked. Using company ID:', companyId);
                                                            generateRegistrationCode(companyId);
                                                        }}
                                                        className="btn btn-primary"
                                                        style={{ width: '100%', padding: '1rem' }}
                                                        disabled={companyDevices.length >= localCompany?.max_screens}
                                                    >
                                                        <Monitor size={18} /> Vincular Nueva Pantalla
                                                    </button>
                                                    {companyDevices.length > 0 && (
                                                        <button
                                                            onClick={() => unlinkAllDevices(localCompany?.id)}
                                                            className="btn btn-secondary"
                                                            style={{ width: '100%', marginTop: '0.5rem', color: 'var(--error)', borderColor: 'var(--error)' }}
                                                        >
                                                            <Trash2 size={18} /> Desvincular Todo
                                                        </button>
                                                    )}
                                                </div>
                                            </div>
                                            <div className="devices-list" style={{ marginTop: '1.5rem', display: 'flex', flexDirection: 'column', gap: '0.8rem' }}>
                                                {companyDevices.length > 0 ? companyDevices.map(d => (
                                                    <div key={d.id} className="glass-card" style={{ display: 'flex', justifyContent: 'space-between', padding: '1rem', background: 'var(--bg-surface)', border: '1px solid var(--border-color)' }}>
                                                        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                                                            <div style={{ width: 12, height: 12, borderRadius: '50%', background: '#10b981', boxShadow: '0 0 10px rgba(16,185,129,0.5)' }}></div>
                                                            <div>
                                                                <div style={{ fontWeight: 'bold' }}>{d.name}</div>
                                                                <div style={{ fontSize: '0.7rem', opacity: 0.5 }}>UUID: {d.uuid}</div>
                                                            </div>
                                                        </div>
                                                        <span style={{ fontSize: '0.7rem', background: 'rgba(16, 185, 129, 0.1)', color: '#10b981', padding: '2px 8px', borderRadius: '4px' }}>Online</span>
                                                        <div style={{ display: 'flex', gap: '0.5rem', marginLeft: 'auto' }}>
                                                            <Tooltip text="Identificar esta Pantalla">
                                                                <button onClick={() => handlePingTV(d.uuid)} className="action-btn" style={{ background: 'rgba(251, 191, 36, 0.1)', border: 'none', color: '#fbbf24', cursor: 'pointer' }}><Wifi size={16} /></button>
                                                            </Tooltip>
                                                            <button onClick={() => handleRenameClick(d)} className="action-btn edit" style={{ background: 'none', border: 'none', color: 'var(--text-main)', cursor: 'pointer' }}><Edit size={16} /></button>
                                                            <button onClick={() => deleteDevice(d.uuid)} className="action-btn delete" style={{ background: 'none', border: 'none', color: 'var(--error)', cursor: 'pointer' }}><Trash2 size={16} /></button>
                                                        </div>
                                                    </div>
                                                )) : (
                                                    <div style={{ textAlign: 'center', padding: '3rem', background: 'var(--bg-app)', borderRadius: '12px', opacity: 0.5 }}>
                                                        <Monitor size={48} style={{ marginBottom: '1rem' }} />
                                                        <p>Aún no hay pantallas vinculadas.</p>
                                                    </div>
                                                )}
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            );
                        })()}


                        {/* {clientTab === 'management' && (
                            <MenuEditor companyId={localCompany.id} token={token} />
                        )} */}

                        {clientTab === 'sidebar_tab' && (
                            <SidebarEditor
                                company={localCompany}
                                onChange={handleLocalChange}
                                disabled={loading}
                            />
                        )}

                        {clientTab === 'bottombar_tab' && (
                            <BottomBarEditor
                                company={localCompany}
                                onChange={handleLocalChange}
                                disabled={localCompany?.plan?.toLowerCase() === 'free'}
                            />
                        )}

                        {clientTab === 'messaging' && (
                            <MessagingSystem
                                company={localCompany}
                                token={token}
                            />
                        )}

                        {clientTab === 'videos' && (
                            <VideoEditor company={localCompany} onChange={handleLocalChange} />
                        )}

                        {clientTab === 'users' && (
                            <ClientUserManagement company={company} token={token} />
                        )}

                        {clientTab === 'helpdesk' && (
                            <Helpdesk token={token} userRole={userRole} />
                        )}

                    </div>
                </div>

                {/* VISUALIZER SIDE (STICKY) */}
                <div style={{ position: 'sticky', top: '1rem', height: 'fit-content', width: '100%' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                        <h2 style={{ fontSize: '1rem', margin: 0, display: 'flex', alignItems: 'center', gap: '0.4rem', color: 'var(--primary-color)' }}>
                            <Monitor size={18} /> Previsualización Real Time
                        </h2>
                        <div style={{ fontSize: '0.65rem', background: 'rgba(16, 185, 129, 0.1)', color: '#10b981', padding: '0.2rem 0.5rem', borderRadius: '20px', fontWeight: 'bold', border: '1px solid rgba(16, 185, 129, 0.2)' }}>VenrideScreenS</div>
                    </div>

                    <div style={{
                        width: '100%',
                        maxWidth: '100%',
                        background: '#0a0a0a',
                        borderRadius: '16px',
                        overflow: 'hidden',
                        boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.5)',
                        border: '1px solid rgba(255, 255, 255, 0.05)',
                        display: 'flex',
                        flexDirection: 'column'
                    }}>
                        <div style={{ width: '100%', aspectRatio: '16/9', background: '#000', position: 'relative' }}>
                            <iframe
                                src={`${window.location.protocol}//${window.location.hostname}:8080/?preview=${localCompany?.id}`}
                                style={{ width: '100%', height: '100%', border: 'none' }}
                                title="TV Preview"
                            />
                        </div>
                        <div style={{ padding: '1.2rem', borderTop: '1px solid rgba(255,255,255,0.05)' }}>
                            <div style={{ background: 'rgba(99, 102, 241, 0.05)', padding: '0.8rem', borderRadius: '12px', fontSize: '0.7rem', marginBottom: '1rem', border: '1px solid rgba(99, 102, 241, 0.1)' }}>
                                <strong>Tip:</strong> Sincronización 1:1 activa. Lo que ves aquí es exactamente lo que se muestra en las pantallas.
                            </div>
                            <button className="btn" style={{ width: '100%', fontSize: '0.75rem', justifyContent: 'center' }} onClick={() => {
                                const tvUrl = `${window.location.protocol}//${window.location.hostname}:8080`;
                                window.open(tvUrl, '_blank');
                            }}><Eye size={14} /> Abrir en Pantalla Completa</button>
                        </div>
                    </div>
                </div>
            </div>

            <Modal isOpen={showCompanyModal} onClose={() => setShowCompanyModal(false)} title="Actualizar Perfil de Empresa">
                <CompanyForm company={selectedCompany} onSave={saveCompany} onCancel={() => setShowCompanyModal(false)} isSuperAdmin={view === 'superadmin'} onGenerateCode={generateRegistrationCode} />
            </Modal>

            <Modal isOpen={!!editingDevice} onClose={() => setEditingDevice(null)} title="Renombrar Dispositivo">
                <div style={{ padding: '1rem' }}>
                    <label style={{ display: 'block', marginBottom: '0.5rem' }}>Nuevo Nombre</label>
                    <input
                        type="text"
                        value={renameDeviceName}
                        onChange={e => setRenameDeviceName(e.target.value)}
                        className="form-control"
                        style={{ width: '100%', padding: '0.8rem', marginBottom: '1.5rem', background: 'rgba(255,255,255,0.05)', color: '#fff', border: '1px solid rgba(255,255,255,0.1)' }}
                        autoFocus
                    />
                    <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '1rem' }}>
                        <button onClick={() => setEditingDevice(null)} className="btn btn-secondary">Cancelar</button>
                        <button onClick={handleRenameSubmit} className="btn btn-primary">Guardar Cambios</button>
                    </div>
                </div>
            </Modal>

            <ChatWidget token={token} currentUser={userObj} plan={localCompany?.plan} />

            {/* GLOBAL REPLACEMENT MODALS */}
            {confirmModalData && <Modal isOpen={!!confirmModalData} onClose={() => setConfirmModalData(null)} title={confirmModalData.title || "Confirmación"}>
                <div style={{ textAlign: 'center', padding: '1rem' }}>
                    <p style={{ fontSize: '1.1rem', marginBottom: '1.5rem', color: 'var(--text-main)' }}>{confirmModalData.message}</p>
                    <div style={{ display: 'flex', gap: '1rem', justifyContent: 'center' }}>
                        <button onClick={() => setConfirmModalData(null)} className="btn btn-secondary" style={{ flex: 1 }}>{confirmModalData.cancelText || "Cancelar"}</button>
                        <button onClick={() => { if (confirmModalData.onConfirm) confirmModalData.onConfirm(); setConfirmModalData(null); }} className={`btn btn-${confirmModalData.type === 'danger' ? 'danger' : 'primary'}`} style={{ flex: 1 }}>{confirmModalData.confirmText || "Confirmar"}</button>
                    </div>
                </div>
            </Modal>}
            {alertModalData && <Modal isOpen={!!alertModalData} onClose={() => setAlertModalData(null)} title={alertModalData.title || "Aviso"}>
                <div style={{ textAlign: 'center', padding: '1rem' }}>
                    <div style={{ marginBottom: '1rem' }}>{alertModalData.type === 'error' ? <XCircle size={40} color="var(--error)" /> : <CheckCircle size={40} color="var(--success)" />}</div>
                    <p style={{ fontSize: '1.1rem', marginBottom: '1.5rem', color: 'var(--text-main)' }}>{alertModalData.message}</p>
                    <button onClick={() => setAlertModalData(null)} className="btn btn-primary" style={{ width: '100%' }}>Aceptar</button>
                </div>
            </Modal>}
        </div>
    );
}

// --- SUB-COMPONENTS ---

const OperatorView = ({ company, token, onLogout }) => {
    const [youtubeUrl, setYoutubeUrl] = useState(company?.priority_content_url || '');
    const [loading, setLoading] = useState(false);

    useEffect(() => {
        if (company) setYoutubeUrl(company.priority_content_url || '');
    }, [company]);

    const handleSave = async () => {
        setLoading(true);
        try {
            const res = await fetch(`${API_BASE}/companies/${company.id}`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
                body: JSON.stringify({ priority_content_url: youtubeUrl })
            });
            if (res.ok) alert("URL Actualizada Correctamente");
            else alert("Error al guardar");
        } catch (e) { alert("Error de conexión"); }
        finally { setLoading(false); }
    };

    return (
        <div className="dashboard-container">
            <header className="dash-header">
                <div><h1>Panel de Operador</h1><p>{company?.name}</p></div>
                <button onClick={onLogout} className="btn"><LogOut size={18} /></button>
            </header>
            <div className="glass-card" style={{ maxWidth: '800px', margin: '2rem auto' }}>
                <h3>Gestión de Contenido TV</h3>
                <div style={{ margin: '1.5rem 0' }}>
                    <label>URL de YouTube / Contenido Prioritario</label>
                    <div style={{ display: 'flex', gap: '1rem' }}>
                        <input value={youtubeUrl} onChange={e => setYoutubeUrl(e.target.value)} placeholder="https://youtube.com/..." style={{ flex: 1 }} />
                        <button onClick={handleSave} className="btn btn-primary" disabled={loading}>{loading ? 'Guardando...' : 'Guardar'}</button>
                    </div>
                </div>
                <div style={{ marginTop: '2rem', borderTop: '1px solid var(--border-color)', paddingTop: '1rem' }}>
                    <h4>Previsualización TV</h4>
                    <iframe
                        src={`${window.location.protocol}//${window.location.hostname}:8080/?preview=${company?.id}`}
                        style={{ width: '100%', height: '400px', border: 'none', borderRadius: '12px', background: '#000' }}
                        title="TV Preview"
                    />
                </div>
            </div>
        </div>
    );
};

const ClientUserManagement = ({ company, token }) => {
    const [users, setUsers] = useState([]);
    const [password, setPassword] = useState('');
    const [selectedUser, setSelectedUser] = useState(null);

    useEffect(() => {
        fetch(`${API_BASE}/admin/users/`, { headers: { 'Authorization': `Bearer ${token}` } })
            .then(res => res.json())
            .then(data => setUsers(Array.isArray(data) ? data : []))
            .catch(e => console.error(e));
    }, [token]);

    const handleUpdatePass = async () => {
        if (!password) return;
        try {
            const res = await fetch(`${API_BASE}/admin/users/${selectedUser.id}/password`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
                body: JSON.stringify({ password })
            });
            if (res.ok) { alert("Contraseña actualizada"); setPassword(''); setSelectedUser(null); }
            else alert("Error al actualizar");
        } catch (e) { alert("Error"); }
    };

    return (
        <div className="glass-card">
            <h3>Gestión de Operadores</h3>
            <table className="admin-table">
                <thead><tr><th>Usuario (Email)</th><th>Rol</th><th>Acción</th></tr></thead>
                <tbody>
                    {users.filter(u => u.role === 'operador_empresa').map(u => (
                        <tr key={u.id}>
                            <td>{u.username}</td>
                            <td>Operador</td>
                            <td>
                                <button className="btn" onClick={() => setSelectedUser(u)}><Key size={14} /> Cambiar Clave</button>
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
            {selectedUser && (
                <div className="modal-overlay">
                    <div className="modal-content">
                        <h3>Nueva Clave para {selectedUser.username}</h3>
                        <input type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="Nueva contraseña" />
                        <div style={{ marginTop: '1rem', display: 'flex', gap: '1rem' }}>
                            <button onClick={handleUpdatePass} className="btn btn-primary">Guardar</button>
                            <button onClick={() => setSelectedUser(null)} className="btn">Cancelar</button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

// --- SUB-COMPONENTS ---

const ThemeSwitch = ({ theme, toggle }) => (
    <div className="theme-switch-container" onClick={toggle} title={`Cambiar a modo ${theme === 'dark' ? 'claro' : 'oscuro'}`}>
        <div className={`theme-switch-track ${theme}`}>
            <div className="theme-switch-handle">
                {theme === 'dark' ? <Moon size={12} fill="currentColor" /> : <Sun size={12} fill="currentColor" />}
            </div>
        </div>
        <span style={{ fontSize: '0.7rem', fontWeight: '600', opacity: 0.8, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
            {theme === 'dark' ? 'Modo Oscuro' : 'Modo Claro'}
        </span>
    </div>
);

const BrandingEditor = ({ company, onChange }) => {
    const ds = company?.design_settings || {};
    const update = (k, v) => onChange({ design_settings: { ...ds, [k]: v } });

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div className="grid-2">
                <div>
                    <label style={{ fontSize: '0.75rem' }}>Fuente del Título</label>
                    <select value={ds.name_font || 'inherit'} onChange={e => update('name_font', e.target.value)}>
                        <option value="inherit">Inherit</option>
                        <option value="'Inter', sans-serif">Inter</option>
                        <option value="'Roboto', sans-serif">Roboto</option>
                        <option value="'Outfit', sans-serif">Outfit</option>
                        <option value="serif">Serif</option>
                        <option value="monospace">Monospace</option>
                    </select>
                </div>
                <div>
                    <label style={{ fontSize: '0.75rem' }}>Color del Título</label>
                    <input type="color" value={ds.name_color || '#ffffff'} onChange={e => update('name_color', e.target.value)} />
                </div>
            </div>
            <div className="grid-2">
                <div>
                    <label style={{ fontSize: '0.75rem' }}>Tamaño ({ds.name_size || '1.2rem'})</label>
                    <input type="range" min="0.8" max="4" step="0.1" value={parseFloat(ds.name_size) || 1.2} onChange={e => update('name_size', `${e.target.value}rem`)} />
                </div>
                <div>
                    <label style={{ fontSize: '0.75rem' }}>Grosor</label>
                    <select value={ds.name_weight || 'bold'} onChange={e => update('name_weight', e.target.value)}>
                        <option value="normal">Normal</option>
                        <option value="bold">Bold (Negrita)</option>
                        <option value="900">Black (Grueso)</option>
                    </select>
                </div>
            </div>
        </div>
    );
};

const CompanyForm = ({ company, isSuperAdmin, activeUsers, activeDevices, onSave, onCancel, onChange, onGenerateCode }) => {
    const [formData, setFormData] = useState({
        name: '', username: '', password: '', max_screens: 2, is_active: true,
        valid_until: '', client_editable_fields: 'name,layout_type,logo_url,sidebar_content,bottom_bar_content,pause_duration',
        priority_content_url: '', video_source: 'youtube', filler_keywords: 'nature, food', google_drive_link: '',
        plan: 'free',
        design_settings: { name_font: 'inherit', name_color: '#ffffff', name_size: '1.2rem', name_weight: 'bold' }
    });

    useEffect(() => {
        if (company) {
            const formattedDate = company.valid_until ? new Date(company.valid_until).toISOString().split('T')[0] : '';
            setFormData({ ...company, valid_until: formattedDate });
        }
    }, [company]);

    const isPermitted = (field) => (formData.client_editable_fields || '').split(',').includes(field);
    const togglePermission = (field) => {
        const perms = (formData.client_editable_fields || '').split(',').filter(p => p !== '');
        const newPerms = perms.includes(field) ? perms.filter(p => p !== field) : [...perms, field];
        setFormData({ ...formData, client_editable_fields: newPerms.join(',') });
    };

    useEffect(() => {
        if (onChange) onChange(formData);
    }, [formData]);

    const updateDesign = (updates) => {
        setFormData(prev => ({
            ...prev,
            ...updates,
            design_settings: { ...(prev.design_settings || {}), ...(updates.design_settings || {}) }
        }));
    };

    const handleSubmit = (e) => {
        e.preventDefault();
        onSave(formData);
    };

    return (
        <form onSubmit={handleSubmit} className="company-form-full">
            <div className="form-header">
                <div>
                    <h2 style={{ fontSize: '1.5rem', fontWeight: 'bold' }}>{company ? 'Actualizar Empresa' : 'Configurar Nueva Empresa'}</h2>
                    <p style={{ opacity: 0.6 }}>{company ? `Editando configuración para ${company.name}` : 'Complete los datos para registrar un nuevo cliente'}</p>
                </div>
                <div style={{ display: 'flex', gap: '0.8rem' }}>
                    <button type="button" onClick={onCancel} className="btn">Cerrar</button>
                    <button type="submit" className="btn btn-primary" style={{ padding: '0.6rem 1.5rem' }}>{company ? 'Actualizar cambios' : 'Finalizar Registro'}</button>
                </div>
            </div>

            <div className="form-sections-grid">
                <div className="form-main-content">
                    <section className="form-section">
                        <div className="section-title"><Building size={18} /> Información Comercial y Contacto</div>
                        <div className="section-fields">
                            <div className="field-group">
                                <label>Nombre Comercial</label>
                                <input value={formData.name} onChange={e => setFormData({ ...formData, name: e.target.value })} required placeholder="Ej: Venrides C.A." />
                            </div>
                            <div className="field-group">
                                <label>RIF / Documento</label>
                                <input value={formData.rif || ''} onChange={e => setFormData({ ...formData, rif: e.target.value })} placeholder="J-12345678-9" />
                            </div>
                            <div className="field-group">
                                <label>Email Público</label>
                                <input value={formData.email || ''} onChange={e => setFormData({ ...formData, email: e.target.value })} placeholder="contacto@empresa.com" />
                            </div>
                            <div className="field-group">
                                <label>Teléfono Principal</label>
                                <input value={formData.phone || ''} onChange={e => setFormData({ ...formData, phone: e.target.value })} placeholder="+58..." />
                            </div>
                            <div className="field-group">
                                <label>WhatsApp</label>
                                <input value={formData.whatsapp || ''} onChange={e => setFormData({ ...formData, whatsapp: e.target.value })} />
                            </div>
                            <div className="field-group">
                                <label>Instagram</label>
                                <input value={formData.instagram || ''} onChange={e => setFormData({ ...formData, instagram: e.target.value })} />
                            </div>
                            <div className="field-group">
                                <label>Facebook</label>
                                <input value={formData.facebook || ''} onChange={e => setFormData({ ...formData, facebook: e.target.value })} />
                            </div>
                            <div className="field-group">
                                <label>TikTok</label>
                                <input value={formData.tiktok || ''} onChange={e => setFormData({ ...formData, tiktok: e.target.value })} />
                            </div>
                            <div className="field-group full">
                                <label>Dirección</label>
                                <textarea value={formData.address || ''} onChange={e => setFormData({ ...formData, address: e.target.value })} rows={2}></textarea>
                            </div>
                        </div>
                    </section>

                    <section className="form-section">
                        <div className="section-title"><Palette size={18} /> Apariencia y Branding Avanzado</div>
                        <BrandingEditor company={formData} onChange={updateDesign} />
                        <div className="field-group full" style={{ marginTop: '1.5rem' }}>
                            <label>URL del Logo (Opcional)</label>
                            <input value={formData.logo_url || ''} onChange={e => setFormData({ ...formData, logo_url: e.target.value })} placeholder="https://..." />
                        </div>
                    </section>

                    {/* <section className="form-section">
                        <div className="section-title"><PlaySquare size={18} /> Videos y Contenido (YouTube)</div>
                        <p style={{ fontSize: '0.7rem', opacity: 0.7, marginBottom: '1rem' }}>Gestiona la lista de reproducción de la TV. Asigna hasta 3 URLs de YouTube.</p>
                        <VideoEditor
                            company={formData}
                            onChange={(updates) => setFormData(prev => ({ ...prev, ...updates }))}
                        />
                    </section> */}
                </div>

                <div className="form-sidebar-content">
                    <section className="form-section accent">
                        {/* ACTIVE USERS SECTION (New) */}
                        {isSuperAdmin && activeUsers && (
                            <div style={{ marginBottom: '2rem', borderBottom: '1px solid var(--border-color)', paddingBottom: '1rem' }}>
                                <div className="section-title"><Users size={18} /> Usuarios Activos</div>
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', marginTop: '0.8rem' }}>
                                    {activeUsers.length > 0 ? activeUsers.map(u => (
                                        <div key={u.id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.8rem', padding: '0.5rem', background: 'rgba(255,255,255,0.05)', borderRadius: '6px' }}>
                                            <div style={{ display: 'flex', flexDirection: 'column' }}>
                                                <span style={{ fontWeight: '600' }}>{u.username}</span>
                                                <span className={`badge-role ${u.role}`} style={{ fontSize: '0.6rem', width: 'fit-content' }}>
                                                    {u.role === 'admin_empresa' && 'Admin'}
                                                    {u.role === 'operador_empresa' && 'Operador'}
                                                    {u.role === 'user_basic' && 'Básico'}
                                                </span>
                                            </div>
                                            <div style={{ width: 8, height: 8, borderRadius: '50%', background: '#10b981' }}></div>
                                        </div>
                                    )) : <p style={{ opacity: 0.5, fontStyle: 'italic', fontSize: '0.8rem' }}>Sin usuarios asignados</p>}
                                </div>
                            </div>
                        )}

                        <div className="section-title"><ShieldCheck size={18} /> Membresía y Plan</div>
                        <div className="section-fields" style={{ gridTemplateColumns: '1fr' }}>
                            <div className="field-group">
                                <label>Nivel de Plan (Membresía)</label>
                                <select
                                    value={formData.plan?.toLowerCase() || 'free'}
                                    onChange={e => {
                                        const p = e.target.value;
                                        const limits = { free: 2, basic: 5, plus: 10, ultra: 20 };
                                        setFormData(prev => ({ ...prev, plan: p, max_screens: limits[p] }));
                                    }}
                                    style={{ border: '2px solid var(--primary-color)', fontWeight: 'bold' }}
                                >
                                    <option value="free">GRATUITO (2 TVs)</option>
                                    <option value="basic">BÁSICO (5 TVs)</option>
                                    <option value="plus">PLUS (10 TVs)</option>
                                    <option value="ultra">ULTRA (20 TVs)</option>
                                </select>
                            </div>
                            <div className="field-group">
                                <label>Pantallas Máximas (Manual)</label>
                                <input type="number" value={formData.max_screens} onChange={e => setFormData({ ...formData, max_screens: parseInt(e.target.value) })} required min="1" />
                            </div>

                            {/* DEVICE MANAGEMENT IN SIDEBAR (New) */}
                            {isSuperAdmin && activeDevices && company && (
                                <div style={{ marginTop: '1rem', padding: '1rem', background: 'rgba(0,0,0,0.2)', borderRadius: '8px' }}>
                                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                                        <label style={{ margin: 0, fontSize: '0.75rem' }}>Dispositivos ({activeDevices.length}/{formData.max_screens})</label>
                                        <button
                                            type="button"
                                            className="btn btn-primary"
                                            style={{ fontSize: '0.7rem', padding: '0.3rem 0.6rem' }}
                                            onClick={() => {
                                                if (activeDevices.length >= formData.max_screens) {
                                                    alert(`Límite de pantallas alcanzado para el plan ${formData.plan} (${formData.max_screens} max). Actualice el plan para vincular más.`);
                                                    return;
                                                }
                                                if (onGenerateCode) onGenerateCode(formData.id);
                                            }}
                                        >
                                            + Vincular
                                        </button>
                                    </div>
                                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
                                        {activeDevices.map(d => (
                                            <div key={d.uuid} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', padding: '4px', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                                                <span>{d.name}</span>
                                                <button type="button" style={{ color: '#ef4444', background: 'none', border: 'none', cursor: 'pointer' }} title="Desvincular">X</button>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            )}

                            <div className="field-group">
                                <label>Fecha Vencimiento</label>
                                <input type="date" value={formData.valid_until} onChange={e => setFormData({ ...formData, valid_until: e.target.value })} />
                            </div>
                            <div className="field-group full">
                                <label>Estado del Servicio</label>
                                <div className="toggle-container" onClick={() => setFormData({ ...formData, is_active: !formData.is_active })}>
                                    <div className={`toggle-switch ${formData.is_active ? 'on' : 'off'}`}></div>
                                    <span style={{ fontSize: '0.8rem', fontWeight: 'bold' }}>{formData.is_active ? 'ACTIVO' : 'SUSPENDIDO'}</span>
                                </div>
                            </div>
                        </div>

                        {!company && (
                            <div className="auth-setup">
                                <h4 style={{ fontSize: '0.75rem', marginBottom: '0.8rem', opacity: 0.8, textTransform: 'uppercase' }}>Credenciales de Acceso</h4>
                                <div className="field-group full">
                                    <label>Usuario Maestro</label>
                                    <div className="input-with-icon">
                                        <Users size={14} />
                                        <input value={formData.username} onChange={e => setFormData({ ...formData, username: e.target.value })} required placeholder="usuario_admin" />
                                    </div>
                                </div>
                                <div className="field-group full">
                                    <label>Contraseña Inicial</label>
                                    <div className="input-with-icon">
                                        <Lock size={14} />
                                        <input type="password" value={formData.password} onChange={e => setFormData({ ...formData, password: e.target.value })} required placeholder="********" />
                                    </div>
                                </div>
                            </div>
                        )}
                    </section>

                    <section className="form-section permissions">
                        <div className="section-title"><Lock size={18} /> Permisos Editables</div>
                        <p style={{ fontSize: '0.7rem', marginBottom: '1rem', opacity: 0.7 }}>Define qué secciones podrá modificar el cliente.</p>
                        <div className="permissions-list">
                            {[
                                { id: 'name', label: 'Nombre Social' },
                                { id: 'rif', label: 'RIF / Documento' },
                                { id: 'address', label: 'Dirección' },
                                { id: 'phone', label: 'Teléfono' },
                                { id: 'whatsapp', label: 'WhatsApp' },
                                { id: 'instagram', label: 'Instagram' },
                                { id: 'facebook', label: 'Facebook' },
                                { id: 'tiktok', label: 'TikTok' },
                                { id: 'email', label: 'Email' },
                                { id: 'layout_type', label: 'Diseño Pantalla' },
                                { id: 'logo_url', label: 'Marca / Logo' },
                                { id: 'sidebar_content', label: 'Barra Lateral' },
                                { id: 'bottom_bar_content', label: 'Barra Inferior' },
                                { id: 'pause_duration', label: 'Tiempos Rotación' },
                                { id: 'google_drive_link', label: 'Videos Propios' }
                            ].map(f => (
                                <div key={f.id} onClick={() => togglePermission(f.id)} className={`permission-item ${isPermitted(f.id) ? 'active' : ''}`}>
                                    {isPermitted(f.id) ? <Check size={12} strokeWidth={3} /> : <X size={12} strokeWidth={3} />}
                                    {f.label}
                                </div>
                            ))}
                        </div>
                    </section>
                </div>
            </div >
        </form >
    );
};

const SeoPanel = ({ token }) => {
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetch(`${API_BASE}/admin/analytics/dashboard`, {
            headers: { 'Authorization': `Bearer ${token}` }
        })
            .then(res => res.json())
            .then(d => {
                setData(d);
                setLoading(false);
            })
            .catch(err => {
                console.error("Error loading analytics:", err);
                setLoading(false);
            });
    }, [token]);

    if (loading) return <div style={{ textAlign: 'center', padding: '2rem' }}>Cargando analítica...</div>;
    if (!data) return <div style={{ textAlign: 'center', padding: '2rem' }}>Sin datos disponibles.</div>;

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
            <div className="stats-grid">
                <div className="stat-card">
                    <div className="value">{data.total_visits || 0}</div>
                    <div className="label">Visitas Totales</div>
                </div>
                <div className="stat-card">
                    <div className="value" style={{ color: '#10b981' }}>{data.visits_today || 0}</div>
                    <div className="label">Hoy</div>
                </div>
                <div className="stat-card">
                    <div className="value" style={{ color: '#6366f1' }}>{data.unique_today || 0}</div>
                    <div className="label">Visitantes Unicos (Hoy)</div>
                </div>
            </div>

            <div className="grid-2">
                <div className="glass-card" style={{ background: 'rgba(255,255,255,0.02)', padding: '1.5rem' }}>
                    <h3 style={{ fontSize: '0.9rem', marginBottom: '1rem', opacity: 0.8 }}>Top Fuentes (Referrers)</h3>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.8rem' }}>
                        {Object.entries(data.referrers || {}).slice(0, 5).map(([ref, count]) => (
                            <div key={ref} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.85rem' }}>
                                <span style={{ opacity: 0.7, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '180px' }}>{ref === "directo" ? "Directo / Desconocido" : ref}</span>
                                <span style={{ fontWeight: 'bold' }}>{count}</span>
                            </div>
                        ))}
                        {Object.keys(data.referrers || {}).length === 0 && <p style={{ fontSize: '0.8rem', opacity: 0.5 }}>No hay datos suficientes.</p>}
                    </div>
                </div>

                <div className="glass-card" style={{ background: 'rgba(255,255,255,0.02)', padding: '1.5rem' }}>
                    <h3 style={{ fontSize: '0.9rem', marginBottom: '1rem', opacity: 0.8 }}>Distribución de Dispositivos</h3>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                        {['mobile', 'desktop', 'tablet'].map(type => {
                            const label = type === 'mobile' ? '📱 Móvil' : type === 'desktop' ? '💻 Escritorio' : '📟 Tablet';
                            const count = data.devices?.[type] || 0;
                            const total = Object.values(data.devices || {}).reduce((a, b) => a + b, 0) || 1;
                            const pct = Math.round((count / total) * 100);
                            if (count === 0 && type !== 'desktop') return null;
                            return (
                                <div key={type}>
                                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.85rem', marginBottom: '0.4rem' }}>
                                        <span>{label}</span>
                                        <span>{pct}% ({count})</span>
                                    </div>
                                    <div style={{ width: '100%', height: '6px', background: 'rgba(255,255,255,0.05)', borderRadius: '10px', overflow: 'hidden' }}>
                                        <div style={{ width: `${pct}%`, height: '100%', background: type === 'mobile' ? '#f43f5e' : '#10b981', borderRadius: '10px' }}></div>
                                    </div>
                                </div>
                            );
                        })}
                    </div>
                </div>
            </div>

            <div className="glass-card" style={{ background: 'rgba(255,255,255,0.02)', padding: '1.5rem' }}>
                <h3 style={{ fontSize: '0.9rem', marginBottom: '1rem', opacity: 0.8 }}>Páginas más Visitadas</h3>
                <div className="table-responsive">
                    <table style={{ width: '100%', fontSize: '0.85rem', borderCollapse: 'collapse' }}>
                        <thead>
                            <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.1)', textAlign: 'left' }}>
                                <th style={{ padding: '0.8rem 0' }}>Ruta (Path)</th>
                                <th style={{ padding: '0.8rem 0', textAlign: 'right' }}>Vistas</th>
                            </tr>
                        </thead>
                        <tbody>
                            {Object.entries(data.top_pages || {}).slice(0, 10).map(([page, count]) => (
                                <tr key={page} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                                    <td style={{ padding: '0.8rem 0', fontFamily: 'monospace', opacity: 0.8 }}>{page}</td>
                                    <td style={{ padding: '0.8rem 0', textAlign: 'right', fontWeight: 'bold' }}>{count}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
};

const EcosystemDashboard = ({ token }) => {
    const [data, setData] = useState(null);
    useEffect(() => {
        fetch(`${API_BASE}/admin/crm/ecosystem-status`, { headers: { 'Authorization': `Bearer ${token}` } })
            .then(res => res.json()).then(setData);
    }, [token]);

    if (!data) return <div>Cargando estatus global...</div>;

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
            <div className="stats-grid">
                <div className="stat-card">
                    <div className="value">{data.companies.active} / {data.companies.total}</div>
                    <div className="label">Empresas Activas</div>
                </div>
                <div className="stat-card">
                    <div className="value" style={{ color: '#10b981' }}>${data.revenue.last_30_days}</div>
                    <div className="label">Revenue (30d)</div>
                </div>
                <div className="stat-card">
                    <div className="value" style={{ color: '#fbbf24' }}>{data.tech.total_screens}</div>
                    <div className="label">Pantallas en Red</div>
                </div>
            </div>

            <div className="grid-2">
                <div className="glass-card" style={{ background: 'rgba(0,0,0,0.2)' }}>
                    <h3 style={{ fontSize: '0.9rem', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}><Calendar size={16} /> Próximas Actividades</h3>
                    {data.next_activities.map((a, i) => (
                        <div key={i} style={{ padding: '0.5rem 0', borderBottom: '1px solid rgba(255,255,255,0.05)', display: 'flex', justifyContent: 'space-between', fontSize: '0.85rem' }}>
                            <span>{a.title}</span>
                            <span style={{ opacity: 0.6 }}>{new Date(a.date).toLocaleDateString()}</span>
                        </div>
                    ))}
                </div>
                <div className="glass-card" style={{ background: 'rgba(0,0,0,0.2)' }}>
                    <h3 style={{ fontSize: '0.9rem', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}><ShieldCheck size={16} /> Salud del Sistema</h3>
                    <div style={{ fontSize: '0.85rem', opacity: 0.8 }}>
                        <p>✅ Backend: Operativo</p>
                        <p>✅ Base de Datos: Sincronizada</p>
                        <p>✅ Backups: {data.backup_status}</p>
                    </div>
                </div>
            </div>
        </div>
    );
};

const CrmPanel = ({ token }) => {
    const [templates, setTemplates] = useState([]);
    const [activities, setActivities] = useState([]);

    useEffect(() => {
        fetch(`${API_BASE}/admin/crm/templates`, { headers: { 'Authorization': `Bearer ${token}` } }).then(res => res.json()).then(setTemplates);
        fetch(`${API_BASE}/admin/crm/calendar`, { headers: { 'Authorization': `Bearer ${token}` } }).then(res => res.json()).then(setActivities);
    }, [token]);

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
            <section>
                <h3 style={{ fontSize: '1.1rem', marginBottom: '1rem' }}>Gestión de Plantillas Auto</h3>
                <div className="grid-2">
                    {['welcome', 'apk_download', 'expiry_7', 'expiry_1', 'birthday'].map(t => (
                        <div key={t} className="glass-card" style={{ padding: '1rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <div style={{ textTransform: 'capitalize' }}>{t.replace('_', ' ')}</div>
                            <div style={{ display: 'flex', gap: '0.5rem' }}>
                                <button className="btn" style={{ fontSize: '0.7rem' }}>Editar</button>
                                <div className="badge-status active" style={{ fontSize: '0.6rem' }}>AUTO: ON</div>
                            </div>
                        </div>
                    ))}
                </div>
            </section>

            <section>
                <h3 style={{ fontSize: '1.1rem', marginBottom: '1rem' }}>Calendario de Marketing (Venezuela 🇻🇪)</h3>
                <div className="table-responsive">
                    <table className="admin-table">
                        <thead><tr><th>Fecha</th><th>Evento</th><th>Tipo</th><th>Acción Auto</th></tr></thead>
                        <tbody>
                            {activities.map((a, i) => (
                                <tr key={i}>
                                    <td>{new Date(a.activity_date).toLocaleDateString()}</td>
                                    <td>{a.title}</td>
                                    <td>{a.is_holiday ? 'Feriado' : 'Actividad'}</td>
                                    <td>{a.send_auto_greeting ? '✅ Saludo' : 'Manual'}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </section>
        </div>
    );
};

const SalesPanel = ({ token }) => {
    const [promos, setPromos] = useState([]);
    const [affiliates, setAffiliates] = useState([]);

    useEffect(() => {
        fetch(`${API_BASE}/admin/crm/promotions`, { headers: { 'Authorization': `Bearer ${token}` } }).then(res => res.json()).then(setPromos);
        fetch(`${API_BASE}/admin/crm/affiliates`, { headers: { 'Authorization': `Bearer ${token}` } }).then(res => res.json()).then(setAffiliates);
    }, [token]);

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
            <div className="grid-2">
                <div className="glass-card">
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '1rem' }}>
                        <h3 style={{ fontSize: '1rem' }}><Gift size={18} /> Promociones Activas</h3>
                        <button className="btn btn-primary" style={{ padding: '2px 8px', fontSize: '0.7rem' }}>+ Nueva</button>
                    </div>
                    {promos.map((p, i) => (
                        <div key={i} style={{ padding: '0.5rem', background: 'rgba(255,255,255,0.03)', borderRadius: '8px', marginBottom: '0.5rem', fontSize: '0.8rem' }}>
                            <div style={{ fontWeight: 'bold' }}>{p.code} ({p.discount_pct}%)</div>
                            <div style={{ opacity: 0.6 }}>{p.name}</div>
                        </div>
                    ))}
                </div>
                <div className="glass-card">
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '1rem' }}>
                        <h3 style={{ fontSize: '1rem' }}><Target size={18} /> Marketing de Afiliados</h3>
                        <button className="btn btn-primary" style={{ padding: '2px 8px', fontSize: '0.7rem' }}>+ Reclutar</button>
                    </div>
                    {affiliates.map((af, i) => (
                        <div key={i} style={{ padding: '0.5rem', display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                            <span>{af.name}</span>
                            <span style={{ fontWeight: 'bold', color: '#10b981' }}>{af.total_referred} Refs</span>
                        </div>
                    ))}
                </div>
            </div>

            <div className="glass-card">
                <h3 style={{ fontSize: '1.1rem', marginBottom: '1rem' }}>Marketing Social Status</h3>
                <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
                    {['Instagram', 'Facebook', 'TikTok', 'WhatsApp'].map(plat => (
                        <div key={plat} style={{ flex: 1, minWidth: '150px', background: 'rgba(255,255,255,0.03)', padding: '1rem', borderRadius: '12px', textAlign: 'center' }}>
                            <div style={{ fontSize: '0.9rem', fontWeight: 'bold' }}>{plat}</div>
                            <div style={{ fontSize: '0.7rem', opacity: 0.6 }}>Tracking Links: OK</div>
                            <button className="btn" style={{ width: '100%', marginTop: '0.5rem', fontSize: '0.7rem' }}>Ver Dashboard</button>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
};

const MasterAdManager = ({ token }) => {
    const [ad, setAd] = useState({ video_playlist: ['', '', ''], ticker_messages: [], ad_scripts: [] });
    const [loading, setLoading] = useState(false);
    const [newTicker, setNewTicker] = useState('');
    const [newScript, setNewScript] = useState('');

    useEffect(() => {
        fetch(`${API_BASE}/admin/global-ad`, { headers: { 'Authorization': `Bearer ${token}` } })
            .then(res => res.json())
            .then(data => {
                setAd({
                    video_playlist: Array.isArray(data.video_playlist) ? data.video_playlist : [data.video_url || '', '', ''],
                    ticker_messages: Array.isArray(data.ticker_messages) ? data.ticker_messages : [],
                    ad_scripts: Array.isArray(data.ad_scripts) ? data.ad_scripts : []
                });
            })
            .catch(err => console.error("Error loading global ad:", err));
    }, []);

    const handleSave = async () => {
        setLoading(true);
        try {
            await fetch(`${API_BASE}/admin/global-ad`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
                body: JSON.stringify(ad)
            });
            alert("Publicidad Global Actualizada");
        } catch (err) { alert("Error al guardar"); }
        setLoading(false);
    };

    const addTicker = () => {
        if (!newTicker.trim()) return;
        setAd({ ...ad, ticker_messages: [...ad.ticker_messages, newTicker.trim()] });
        setNewTicker('');
    };

    const addScript = () => {
        if (!newScript.trim()) return;
        setAd({ ...ad, ad_scripts: [...ad.ad_scripts, newScript.trim()] });
        setNewScript('');
    };

    const updateVideo = (idx, val) => {
        const next = [...ad.video_playlist];
        while (next.length < 3) next.push('');
        next[idx] = val;
        setAd({ ...ad, video_playlist: next });
    };

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
            <div className="grid-2">
                <div className="glass-card" style={{ padding: '1.5rem' }}>
                    <h3 style={{ fontSize: '1rem', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <PlayCircle size={18} color="var(--primary-color)" /> Playlist Publicitaria (Max 3)
                    </h3>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.8rem' }}>
                        {[0, 1, 2].map(idx => (
                            <div key={idx}>
                                <label style={{ fontSize: '0.65rem', opacity: 0.6 }}>URL Video {idx + 1}</label>
                                <input value={ad.video_playlist[idx] || ''} onChange={e => updateVideo(idx, e.target.value)} placeholder="https://youtube.com/..." />
                            </div>
                        ))}
                    </div>
                </div>

                <div className="glass-card" style={{ padding: '1.5rem' }}>
                    <h3 style={{ fontSize: '1rem', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <Type size={18} color="var(--primary-color)" /> Cintillo Rotativo
                    </h3>
                    <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem' }}>
                        <input value={newTicker} onChange={e => setNewTicker(e.target.value)} placeholder="Nuevo mensaje..." style={{ marginBottom: 0 }} />
                        <button className="btn" onClick={addTicker}><Plus size={16} /></button>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                        {ad.ticker_messages.map((m, i) => (
                            <div key={i} style={{ display: 'flex', justifyContent: 'space-between', background: 'rgba(255,255,255,0.05)', padding: '0.5rem', borderRadius: '6px', fontSize: '0.85rem' }}>
                                <span>{m}</span>
                                <button style={{ border: 'none', background: 'none', color: '#f43f5e', cursor: 'pointer' }} onClick={() => setAd({ ...ad, ticker_messages: ad.ticker_messages.filter((_, idx) => idx !== i) })}><Trash2 size={14} /></button>
                            </div>
                        ))}
                    </div>
                </div>
            </div>

            <div className="glass-card" style={{ padding: '1.5rem' }}>
                <h3 style={{ fontSize: '1rem', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <ShieldCheck size={18} color="var(--primary-color)" /> Scripts Publicitarios (Scripts Google/Meta)
                </h3>
                <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem' }}>
                    <textarea value={newScript} onChange={e => setNewScript(e.target.value)} placeholder="Pega el código del script aquí..." rows={2} style={{ flex: 1, marginBottom: 0 }} />
                    <button className="btn" onClick={addScript} style={{ alignSelf: 'flex-end' }}><Plus size={16} /></button>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: '1rem' }}>
                    {ad.ad_scripts.map((s, i) => (
                        <div key={i} style={{ position: 'relative', background: '#000', padding: '0.5rem', borderRadius: '6px', fontSize: '0.7rem', maxHeight: '100px', overflow: 'hidden', border: '1px solid rgba(255,255,255,0.1)' }}>
                            <code style={{ opacity: 0.5 }}>{s.substring(0, 100)}...</code>
                            <button style={{ position: 'absolute', top: '5px', right: '5px', border: 'none', background: 'rgba(244, 63, 94, 0.8)', color: 'white', borderRadius: '4px', cursor: 'pointer', padding: '2px' }} onClick={() => setAd({ ...ad, ad_scripts: ad.ad_scripts.filter((_, idx) => idx !== i) })}><X size={12} /></button>
                        </div>
                    ))}
                </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', color: '#fbbf24', fontSize: '0.8rem' }}>
                    <AlertCircle size={16} />
                    <span>Solo visible en planes <strong>FREE</strong>.</span>
                </div>
                <button className="btn btn-primary" onClick={handleSave} disabled={loading} style={{ padding: '0.8rem 2.5rem' }}>
                    {loading ? 'Guardando...' : 'Publicar Cambios Masivos'}
                </button>
            </div>
        </div>
    );
};

const PaymentForm = ({ companies, onSave, onCancel }) => {
    const [data, setData] = useState({ company_id: companies[0]?.id || '', amount: 0, payment_method: 'transfer', description: 'Mensualidad TV Screen', payment_date: new Date().toISOString() });
    return (
        <form onSubmit={e => { e.preventDefault(); onSave(data); }} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div>
                <label>Empresa Destino</label>
                <select value={data.company_id} onChange={e => setData({ ...data, company_id: parseInt(e.target.value) })} required>
                    <option value="">Seleccione...</option>
                    {companies.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
                </select>
            </div>
            <div className="grid-2">
                <div><label>Monto (USD)</label><input type="number" step="0.01" value={data.amount} onChange={e => setData({ ...data, amount: parseFloat(e.target.value) })} required /></div>
                <div>
                    <label>Metodo</label>
                    <select value={data.payment_method} onChange={e => setData({ ...data, payment_method: e.target.value })}>
                        <option value="transfer">Transferencia</option>
                        <option value="cash">Efectivo</option>
                        <option value="zelle">Zelle / Otros</option>
                    </select>
                </div>
            </div>
            <div><label>Descripción / Nota</label><input value={data.description} onChange={e => setData({ ...data, description: e.target.value })} /></div>
            <button type="submit" className="btn btn-primary" style={{ marginTop: '0.5rem' }}>Registrar Pago</button>
        </form>
    );
};

const SidebarEditor = ({ company, onChange, disabled }) => {
    const ds = company?.design_settings || {};
    const content = company?.sidebar_content || [];
    const updateDesign = (f, v) => !disabled && onChange({ design_settings: { ...ds, [f]: v } });
    const updateContent = (val) => !disabled && onChange({ sidebar_content: val });

    const addGroup = () => {
        const newGroup = { items: [{ type: 'text', value: 'Promotion', font_size: '1.4rem', color: '#ffffff', weight: 'bold' }], duration: 10 };
        updateContent([...content, newGroup]);
    };

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', opacity: disabled ? 0.6 : 1 }}>
            <div className="glass-card" style={{ borderLeft: '4px solid var(--primary-color)' }}>
                <div className="section-title"><Palette size={18} /> Diseño Lateral <Tooltip text="Ajuste el ancho y estilo visual de la barra lateral." /></div>
                <div className="grid-2">
                    <div><label>Ancho (%)</label><input type="range" min="15" max="45" value={ds.sidebar_width || 22} onChange={e => updateDesign('sidebar_width', parseInt(e.target.value))} /></div>
                    <div><label>Efecto</label><select value={ds.sidebar_effect || 'none'} onChange={e => updateDesign('sidebar_effect', e.target.value)}><option value="none">Normal</option><option value="glass_3d">Cristal</option><option value="neon_glow">Neón</option></select></div>
                </div>
                <div className="grid-2" style={{ marginTop: '1rem' }}>
                    <div><label>Fondo</label><input type="color" value={ds.sidebar_bg || '#1e293b'} onChange={e => updateDesign('sidebar_bg', e.target.value)} /></div>
                    <div><label>Texto</label><input type="color" value={ds.sidebar_text || '#ffffff'} onChange={e => updateDesign('sidebar_text', e.target.value)} /></div>
                </div>
            </div>
            <div className="glass-card">
                <div className="section-title"><Layout size={18} /> Logo y Encabezado <Tooltip text="Configure el logo y el texto fijo superior." /></div>
                <input value={company?.logo_url || ''} onChange={e => onChange({ logo_url: e.target.value })} placeholder="URL Logo..." />
                <div style={{ marginTop: '1rem' }}>
                    <label>Tipo Encabezado</label>
                    <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem' }}>
                        {['text', 'banner'].map(t => <button key={t} className={`btn ${company?.sidebar_header_type === t ? 'btn-primary' : ''}`} onClick={() => onChange({ sidebar_header_type: t })} style={{ flex: 1 }}>{t.toUpperCase()}</button>)}
                    </div>
                    <input value={company?.sidebar_header_value || ''} onChange={e => onChange({ sidebar_header_value: e.target.value })} placeholder="Valor encabezado..." />
                </div>
            </div>
            <div className="glass-card">
                <div className="section-title"><Layout size={18} /> Publicidad en Barra Lateral <Tooltip text="Configure los bloques de contenido publicitario (Imágenes o Texto)." /></div>

                <div style={{ marginBottom: '1rem' }}>
                    <label>Distribución (Bloques)</label>
                    <div style={{ display: 'flex', gap: '0.5rem' }}>
                        {[1, 2, 3].map(n => (
                            <button
                                key={n}
                                className={`btn ${ds.sidebar_layout === n ? 'btn-primary' : ''}`}
                                onClick={() => updateDesign('sidebar_layout', n)}
                                style={{ flex: 1, fontWeight: 'bold' }}
                            >
                                {n} BLOQUE{n > 1 ? 'S' : ''}
                            </button>
                        ))}
                    </div>
                </div>

                <div className="ad-blocks-grid" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                    {Array.from({ length: ds.sidebar_layout || 1 }).map((_, idx) => {
                        const block = (content[idx] || { type: 'image', value: '', items: [] });
                        const updateBlock = (k, v) => {
                            const newContent = [...content];
                            // Ensure array fits layout
                            while (newContent.length <= idx) newContent.push({ type: 'image', value: '' });
                            newContent[idx] = { ...newContent[idx], [k]: v };
                            updateContent(newContent);
                        };

                        return (
                            <div key={idx} className="glass-card" style={{ background: 'rgba(255,255,255,0.03)', padding: '0.8rem' }}>
                                <div style={{ marginBottom: '0.5rem', fontWeight: 'bold', fontSize: '0.8rem', color: 'var(--primary-color)' }}>BLOQUE #{idx + 1}</div>
                                <div className="grid-2">
                                    <div>
                                        <label>Tipo</label>
                                        <select value={block.type || 'image'} onChange={e => updateBlock('type', e.target.value)}>
                                            <option value="image">Imagen (Drive)</option>
                                            <option value="text">Texto</option>
                                        </select>
                                    </div>
                                    {block.type === 'text' && (
                                        <div><label>Fuente</label><input type="color" value={block.color || '#ffffff'} onChange={e => updateBlock('color', e.target.value)} /></div>
                                    )}
                                </div>

                                <div style={{ marginTop: '0.5rem' }}>
                                    <label>{block.type === 'image' ? 'URL Imagen (Drive)' : 'Contenido Texto'}</label>
                                    <input
                                        value={block.value || ''}
                                        onChange={e => updateBlock('value', e.target.value)}
                                        placeholder={block.type === 'image' ? 'https://drive.google.com...' : 'Ingrese texto promocional...'}
                                    />
                                </div>
                                {block.type === 'text' && (
                                    <div className="grid-2" style={{ marginTop: '0.5rem' }}>
                                        <div>
                                            <label>Tipografía</label>
                                            <select value={block.font_family || 'inherit'} onChange={e => updateBlock('font_family', e.target.value)}>
                                                <option value="inherit">Defecto</option>
                                                <option value="'Roboto', sans-serif">Roboto</option>
                                                <option value="'Montserrat', sans-serif">Montserrat</option>
                                                <option value="'Oswald', sans-serif">Oswald</option>
                                                <option value="'Playfair Display', serif">Playfair</option>
                                            </select>
                                        </div>
                                        <div style={{ display: 'flex', gap: '0.5rem' }}>
                                            <div style={{ flex: 1 }}><label>Tamaño</label><input type="range" min="0.8" max="3" step="0.1" value={parseFloat(block.font_size) || 1.2} onChange={e => updateBlock('font_size', `${e.target.value}rem`)} /></div>
                                            <div style={{ flex: 1 }}><label>Peso</label><select value={block.weight || 'bold'} onChange={e => updateBlock('weight', e.target.value)}><option value="normal">Normal</option><option value="bold">Bold</option></select></div>
                                        </div>
                                    </div>
                                )}
                            </div>
                        );
                    })}
                </div>
            </div>

            <div className="glass-card">
                <div className="section-title"><Image size={18} /> Logo Inferior <Tooltip text="Logo secundario en la parte baja de la barra lateral." /></div>
                <input value={ds.sidebar_bottom_logo || ''} onChange={e => updateDesign('sidebar_bottom_logo', e.target.value)} placeholder="URL Logo (Drive)..." />
                <div className="grid-2" style={{ marginTop: '0.8rem' }}>
                    <div><label>Tamaño (%)</label><input type="range" min="10" max="100" value={ds.sidebar_bottom_logo_size || 50} onChange={e => updateDesign('sidebar_bottom_logo_size', parseInt(e.target.value))} /></div>
                    <div><label>Visibilidad</label><div className="toggle-container" onClick={() => updateDesign('show_bottom_logo', !ds.show_bottom_logo)}><div className={`toggle-switch ${ds.show_bottom_logo ? 'on' : 'off'}`}></div></div></div>
                </div>
            </div>
        </div>
    );
};

const BottomBarEditor = ({ company, onChange, disabled }) => {
    const data = company?.bottom_bar_content || {};
    const ds = company?.design_settings || {};

    const update = (k, v) => !disabled && onChange({ bottom_bar_content: { ...data, [k]: v } });
    const updateDesign = (k, v) => !disabled && onChange({ design_settings: { ...ds, [k]: v } });

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', opacity: disabled ? 0.6 : 1 }}>
            <div className="glass-card" style={{ borderLeft: '4px solid #10b981' }}>
                <div className="section-title"><Clock size={18} /> Ajustes Barra Inferior <Tooltip text="Ajuste la velocidad del texto y la altura de la franja informativa." /></div>
                <div className="grid-2">
                    <div><label>Velocidad (Seg)</label><input type="range" min="10" max="120" value={ds.ticker_speed || 30} onChange={e => updateDesign('ticker_speed', parseInt(e.target.value))} /></div>
                    <div><label>Alto (%)</label><input type="range" min="5" max="25" value={ds.bottom_bar_height || 10} onChange={e => updateDesign('bottom_bar_height', parseInt(e.target.value))} /></div>
                </div>
            </div>
            <div className="glass-card">
                <div className="section-title"><MessageSquare size={18} /> Contenido Cintillo <Tooltip text="Mensaje que aparece en el texto corrido inferior." /></div>
                <label>Mensaje Estático</label>
                <input value={data.static || ''} onChange={e => update('static', e.target.value)} placeholder="Ej: Bienvenidos a VenrideScreenS" />
                <div className="grid-2" style={{ marginTop: '1rem' }}>
                    <div><label>WhatsApp</label><input value={data.whatsapp || ''} onChange={e => update('whatsapp', e.target.value)} /></div>
                    <div><label>Instagram</label><input value={data.instagram || ''} onChange={e => update('instagram', e.target.value)} /></div>
                </div>

                <div style={{ marginTop: '1rem', paddingTop: '1rem', borderTop: '1px solid var(--border-color)' }}>
                    <label style={{ fontSize: '0.8rem', opacity: 0.8 }}>Tipografía (Ticker y Redes)</label>
                    <div className="grid-2">
                        <div><label>Color Texto</label><input type="color" value={ds.ticker_color || '#ffffff'} onChange={e => updateDesign('ticker_color', e.target.value)} /></div>
                        <div>
                            <label>Fuente</label>
                            <select value={ds.ticker_font || 'inherit'} onChange={e => updateDesign('ticker_font', e.target.value)}>
                                <option value="inherit">Defecto</option>
                                <option value="'Roboto', sans-serif">Roboto</option>
                                <option value="'Montserrat', sans-serif">Montserrat</option>
                                <option value="'Oswald', sans-serif">Oswald</option>
                                <option value="'Playfair Display', serif">Playfair</option>
                            </select>
                        </div>
                    </div>
                </div>
            </div>

            <div className="glass-card">
                <div className="section-title"><DollarSign size={18} /> Tasa BCV <Tooltip text="Muestre automáticamente la tasa del dólar oficial del BCV en el cintillo." /></div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                    <label>Mostrar en TV</label>
                    <div className="toggle-container" onClick={() => updateDesign('show_bcv', !ds.show_bcv)}><div className={`toggle-switch ${ds.show_bcv ? 'on' : 'off'}`}></div></div>
                </div>
                {ds.show_bcv && (
                    <div className="grid-2">
                        <div><label>Color BCV</label><input type="color" value={ds.bcv_color || '#10b981'} onChange={e => updateDesign('bcv_color', e.target.value)} /></div>
                        <div>
                            <label>Fuente BCV</label>
                            <select value={ds.bcv_font || 'inherit'} onChange={e => updateDesign('bcv_font', e.target.value)}>
                                <option value="inherit">Defecto</option>
                                <option value="'Roboto Mono', monospace">Mono</option>
                                <option value="'Oswald', sans-serif">Oswald</option>
                            </select>
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
};

const VideoEditor = ({ company, onChange }) => {
    const playlist = Array.isArray(company?.video_playlist) ? company.video_playlist : ['', '', ''];
    const updatePlaylist = (i, v) => {
        const next = [...playlist];
        while (next.length < 3) next.push('');
        next[i] = v;
        onChange({ video_playlist: next.slice(0, 3) });
    };

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
            <div className="glass-card" style={{ borderLeft: '4px solid #ef4444' }}>
                <div className="section-title"><PlaySquare size={18} /> Playlist (3 URLs)</div>
                {[0, 1, 2].map(i => (
                    <div key={i} style={{ marginBottom: '0.8rem' }}>
                        <label style={{ fontSize: '0.6rem' }}>VIDEO {i + 1}</label>
                        <input value={playlist[i] || ''} onChange={e => updatePlaylist(i, e.target.value)} placeholder="https://youtube..." />
                    </div>
                ))}
            </div>
            <div className="glass-card">
                <div className="section-title"><Bell size={18} /> Publicidad</div>
                <label>Frecuencia de Ads (Cada X videos)</label>
                <input type="number" min="1" max="10" value={company?.ad_frequency || 3} onChange={e => onChange({ ad_frequency: parseInt(e.target.value) })} />
                <div style={{ marginTop: '1rem' }}><label>Video Propio (Drive)</label><input value={company?.google_drive_link || ''} onChange={e => onChange({ google_drive_link: e.target.value })} /></div>
            </div>
        </div>
    );
};

const MessagingSystem = ({ company, token }) => {
    const [msg, setMsg] = useState('');
    const [sending, setSending] = useState(false);

    const sendMessage = async () => {
        if (!msg) return;
        setSending(true);
        try {
            await fetch(`${API_BASE}/companies/${company.id}/message`, {
                method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
                body: JSON.stringify({ text: msg, duration: 10, type: 'alert' })
            });
            setMsg('');
            alert("Mensaje enviado a las pantallas!");
        } catch (e) { alert("Error"); }
        setSending(false);
    };

    return (
        <div className="glass-card" style={{ borderTop: '4px solid #7c3aed' }}>
            <div className="section-title"><MessageSquare size={18} /> Mensajería Instantánea (Live)</div>
            <p style={{ fontSize: '0.7rem', opacity: 0.6, marginBottom: '1.5rem' }}>Envíe avisos urgentes o saludos que aparecerán inmediatamente en todas las TVs.</p>
            <textarea value={msg} onChange={e => setMsg(e.target.value)} placeholder="Escriba su mensaje aquí..." rows={3} style={{ background: 'rgba(0,0,0,0.3)' }}></textarea>
            <button onClick={sendMessage} className="btn btn-primary" style={{ width: '100%', padding: '1rem' }} disabled={sending || !msg}>
                <Power size={18} /> ENVIAR MENSAJE AHORA
            </button>
        </div>
    );
};

const MenuEditor = ({ companyId, token }) => {
    const [items, setItems] = useState([]);
    const [newItem, setNewItem] = useState({ name: '', price: 0, category: 'General', is_available: true });

    useEffect(() => {
        if (companyId) {
            fetch(`${API_BASE}/admin/companies/${companyId}/menus`, { headers: { 'Authorization': `Bearer ${token}` } })
                .then(res => res.json()).then(data => setItems(Array.isArray(data) ? data : [])).catch(e => { });
        }
    }, [companyId, token]);

    const addItem = async () => {
        if (!newItem.name) return;
        try {
            const res = await fetch(`${API_BASE}/admin/companies/${companyId}/menus/`, {
                method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
                body: JSON.stringify(newItem)
            });
            if (res.ok) {
                const added = await res.json();
                setItems([...items, added]);
                setNewItem({ name: '', price: 0, category: 'General', is_available: true });
            }
        } catch (e) { }
    };

    return (
        <div className="form-section">
            <div className="section-title"><HardDrive size={18} /> Menú Digital</div>
            <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr 1fr 50px', gap: '0.5rem', marginBottom: '1rem' }}>
                <input placeholder="Nombre" value={newItem.name} onChange={e => setNewItem({ ...newItem, name: e.target.value })} style={{ marginBottom: 0 }} />
                <input type="number" placeholder="Precio" value={newItem.price} onChange={e => setNewItem({ ...newItem, price: parseFloat(e.target.value) })} style={{ marginBottom: 0 }} />
                <input placeholder="Categoría" value={newItem.category} onChange={e => setNewItem({ ...newItem, category: e.target.value })} style={{ marginBottom: 0 }} />
                <button className="btn btn-primary" onClick={addItem}><Plus size={16} /></button>
            </div>
            <table className="admin-table">
                <tbody>
                    {items.map(i => (
                        <tr key={i.id}>
                            <td>{i.name}</td>
                            <td>{i.category}</td>
                            <td style={{ fontWeight: 'bold' }}>${i.price}</td>
                            <td><button onClick={async () => { await fetch(`${API_BASE}/admin/menus/${i.id}`, { method: 'DELETE', headers: { 'Authorization': `Bearer ${token}` } }); setItems(items.filter(x => x.id !== i.id)); }} className="action-btn suspend"><Trash2 size={12} /></button></td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
};

const UserForm = ({ companies, onSave, onCancel, initialData }) => {
    const [u, setU] = useState(initialData || { username: '', password: '', role: 'operador_empresa', company_id: '' });

    // Update form when initialData changes
    useEffect(() => {
        if (initialData) {
            setU({ ...initialData, password: '' }); // Don't pre-fill password for security
        }
    }, [initialData]);

    const isEditing = !!initialData;

    return (
        <div className="form-section">
            <label>Email / Usuario</label>
            <input
                value={u.username}
                onChange={e => setU({ ...u, username: e.target.value })}
                placeholder="email@ejemplo.com"
                disabled={isEditing} // Email shouldn't change when editing
            />
            <label>{isEditing ? 'Nueva Contraseña (dejar vacío para no cambiar)' : 'Contraseña'}</label>
            <input
                type="password"
                value={u.password}
                onChange={e => setU({ ...u, password: e.target.value })}
                placeholder={isEditing ? "Dejar vacío para mantener actual" : "********"}
            />
            <label>Rol</label>
            <select value={u.role} onChange={e => setU({ ...u, role: e.target.value })}>
                <option value="operador_empresa">Operador Empresa</option>
                <option value="admin_empresa">Admin Empresa</option>
                <option value="admin_master">Admin Master</option>
            </select>
            <label>Empresa (Opcional)</label>
            <select value={u.company_id || ''} onChange={e => setU({ ...u, company_id: e.target.value })}>
                <option value="">Ninguna / Master</option>
                {companies.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
            </select>
            <div style={{ display: 'flex', gap: '1rem', marginTop: '1.5rem' }}>
                <button onClick={() => onSave(u)} className="btn btn-primary" style={{ flex: 1 }}>
                    Guardar
                </button>
                <button onClick={onCancel} className="btn" style={{ flex: 1 }}>Cancelar</button>
            </div>
        </div>
    );
};

const AdminProfileForm = ({ onSave, onCancel }) => {
    const [config, setConfig] = useState({ username: '', password: '' });
    return (
        <div>
            <label>Usuario / Email</label>
            <input value={config.username} onChange={e => setConfig({ ...config, username: e.target.value })} />
            <label>Nueva Contraseña</label>
            <input type="password" value={config.password} onChange={e => setConfig({ ...config, password: e.target.value })} />
            <div style={{ display: 'flex', gap: '1rem' }}><button onClick={() => onSave(config)} className="btn btn-primary" style={{ flex: 1 }}>Guardar</button>
                <button onClick={onCancel} className="btn" style={{ flex: 1 }}>Cerrar</button></div>
        </div>
    );
};

const YouTubePlayer = ({ keywords, isActive, ytReady }) => {
    const playerRef = React.useRef(null);
    const containerRef = React.useRef(null);
    const [isReady, setIsReady] = React.useState(false);
    const lastIdRef = React.useRef(null);

    const extractYoutubeId = (url) => {
        if (!url) return null;
        const regex = /(?:youtube\.com\/(?:[^\/]+\/.+\/|(?:v|e(?:mbed)?|shorts)\/|.*[?&]v=)|youtu\.be\/)([^"&?\/\s]{11})/;
        const match = url.match(regex);
        const result = (match && match[1]) ? match[1] : null;
        console.log("extractYoutubeId result for", url, "is", result);
        return result;
    };

    const getMappedId = (k) => {
        if (!k) return '5qap5aO4i9A';
        const trimmedK = k.toString().trim();
        const lowerK = trimmedK.toLowerCase();

        console.log("YouTubePlayer keywords:", trimmedK);

        if (lowerK.includes('youtube.com') || lowerK.includes('youtu.be')) {
            const extracted = extractYoutubeId(trimmedK);
            console.log("Extracted ID:", extracted);
            return extracted || '5qap5aO4i9A';
        }

        if (lowerK.includes('coffee') || lowerK.includes('jazz')) return 'CH50zuS8dd0';
        if (lowerK.includes('food') || lowerK.includes('restaurant')) return 'J1vL0yW9f70';
        if (lowerK.includes('city') || lowerK.includes('travel')) return 'JB0A8Me8EKk';
        if (lowerK.includes('beach') || lowerK.includes('ocean')) return 'n61ULEU7CO0';
        return '5qap5aO4i9A';
    };

    React.useEffect(() => {
        if (!isActive || !ytReady || !window.YT || !window.YT.Player) return;

        if (!playerRef.current && containerRef.current) {
            const initialId = getMappedId(keywords);
            lastIdRef.current = initialId;
            console.log("YouTubePlayer: Initializing with ID:", initialId);

            playerRef.current = new window.YT.Player(containerRef.current, {
                videoId: initialId,
                playerVars: {
                    autoplay: 1,
                    controls: 0,
                    mute: 1,
                    loop: 1,
                    playlist: initialId,
                    modestbranding: 1,
                    rel: 0
                },
                events: {
                    onReady: (e) => {
                        console.log("YouTubePlayer: Player Ready");
                        setIsReady(true);
                        e.target.playVideo();
                    },
                    onStateChange: (e) => {
                        if (e.data === window.YT.PlayerState.ENDED) {
                            e.target.playVideo(); // Force loop fallback
                        }
                    }
                }
            });
        }
    }, [isActive, ytReady]);

    React.useEffect(() => {
        if (isReady && playerRef.current && typeof playerRef.current.loadVideoById === 'function' && isActive) {
            const newId = getMappedId(keywords);
            if (newId === lastIdRef.current) return;

            console.log("YouTubePlayer updating to newId:", newId);
            lastIdRef.current = newId;

            playerRef.current.loadVideoById({
                videoId: newId
            });

            if (typeof playerRef.current.setPlaylist === 'function') {
                playerRef.current.setPlaylist([newId]);
                playerRef.current.setLoop(true);
            }
        }
    }, [keywords, isReady, isActive]);

    React.useEffect(() => {
        return () => {
            if (playerRef.current && typeof playerRef.current.destroy === 'function') {
                playerRef.current.destroy();
                playerRef.current = null;
            }
        };
    }, []);

    return <div style={{ width: '100%', height: '100%' }}><div ref={containerRef} style={{ width: '100%', height: '100%' }} /></div>;
};

const Helpdesk = ({ token, userRole }) => {
    const [tickets, setTickets] = useState([]);
    const [view, setView] = useState('list'); // list, detail, create
    const [selectedTicket, setSelectedTicket] = useState(null);
    const [newTicket, setNewTicket] = useState({ subject: '', category: 'Technical', priority: 'normal', initial_message: '' });
    const [replyBody, setReplyBody] = useState('');
    const [loading, setLoading] = useState(false);

    useEffect(() => {
        if (view === 'list') fetchTickets();
    }, [view]);

    const fetchTickets = async () => {
        setLoading(true);
        try {
            const res = await fetch(`${API_BASE}/admin/helpdesk/tickets`, { headers: { 'Authorization': `Bearer ${token}` } });
            const data = await res.json();
            setTickets(Array.isArray(data) ? data : []);
        } catch (e) { }
        setLoading(false);
    };

    const fetchTicketDetails = async (id) => {
        setLoading(true);
        try {
            const res = await fetch(`${API_BASE}/admin/helpdesk/tickets/${id}`, { headers: { 'Authorization': `Bearer ${token}` } });
            const data = await res.json();
            setSelectedTicket(data);
            setView('detail');
        } catch (e) { alert("Error al cargar ticket"); }
        setLoading(false);
    };

    const createTicket = async () => {
        try {
            const res = await fetch(`${API_BASE}/admin/helpdesk/tickets`, {
                method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
                body: JSON.stringify(newTicket)
            });
            if (res.ok) {
                alert("Ticket Creado");
                setNewTicket({ subject: '', category: 'Technical', priority: 'normal', initial_message: '' });
                setView('list');
            }
        } catch (e) { alert("Error"); }
    };

    const sendReply = async () => {
        if (!replyBody) return;
        try {
            await fetch(`${API_BASE}/admin/helpdesk/tickets/${selectedTicket.id}/reply`, {
                method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
                body: JSON.stringify({ body: replyBody })
            });
            setReplyBody('');
            fetchTicketDetails(selectedTicket.id); // Refresh
        } catch (e) { alert("Error"); }
    };

    const updateStatus = async (status) => {
        try {
            await fetch(`${API_BASE}/admin/helpdesk/tickets/${selectedTicket.id}/status?status=${status}`, {
                method: 'PATCH', headers: { 'Authorization': `Bearer ${token}` }
            });
            fetchTicketDetails(selectedTicket.id);
        } catch (e) { }
    };

    return (
        <div className="glass-card">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                <h2><LifeBuoy size={24} style={{ marginRight: '0.5rem' }} /> Centro de Ayuda</h2>
                {view === 'list' && (
                    <button className="btn btn-primary" onClick={() => setView('create')}>+ Nuevo Ticket</button>
                )}
                {view !== 'list' && (
                    <button className="btn" onClick={() => setView('list')}>← Volver</button>
                )}
            </div>

            {view === 'list' && (
                <div className="table-responsive">
                    <table className="admin-table">
                        <thead><tr><th>Asunto</th><th>Categoría</th><th>Estado</th><th>Prioridad</th><th>Actualizado</th><th>Acción</th></tr></thead>
                        <tbody>
                            {tickets.map(t => (
                                <tr key={t.id}>
                                    <td style={{ fontWeight: '600' }}>{t.subject}</td>
                                    <td>{t.category}</td>
                                    <td>
                                        <span className={`badge-status ${t.status === 'open' ? 'active' : t.status === 'closed' ? 'inactive' : 'pending'}`}>
                                            {t.status.toUpperCase()}
                                        </span>
                                    </td>
                                    <td>
                                        <span style={{ color: t.priority === 'urgent' ? '#ef4444' : t.priority === 'high' ? '#f59e0b' : '#10b981', fontWeight: 'bold' }}>
                                            {t.priority.toUpperCase()}
                                        </span>
                                    </td>
                                    <td style={{ fontSize: '0.8rem' }}>{new Date(t.updated_at).toLocaleString()}</td>
                                    <td><button className="action-btn view" onClick={() => fetchTicketDetails(t.id)}><Eye size={16} /></button></td>
                                </tr>
                            ))}
                            {tickets.length === 0 && <tr><td colSpan="6" style={{ textAlign: 'center', opacity: 0.5 }}>No hay tickets recientes</td></tr>}
                        </tbody>
                    </table>
                </div>
            )}

            {view === 'create' && (
                <div className="form-section">
                    <h3>Abriendo Nuevo Ticket</h3>
                    <input placeholder="Asunto" value={newTicket.subject} onChange={e => setNewTicket({ ...newTicket, subject: e.target.value })} />
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                        <select value={newTicket.category} onChange={e => setNewTicket({ ...newTicket, category: e.target.value })}>
                            <option value="Technical">Soporte Técnico</option>
                            <option value="Billing">Facturación</option>
                            <option value="Feature">Solicitud de Función</option>
                            <option value="General">General</option>
                        </select>
                        <select value={newTicket.priority} onChange={e => setNewTicket({ ...newTicket, priority: e.target.value })}>
                            <option value="low">Baja</option>
                            <option value="normal">Normal</option>
                            <option value="high">Alta</option>
                            <option value="urgent">Urgente</option>
                        </select>
                    </div>
                    <textarea placeholder="Describa su problema..." rows={5} value={newTicket.initial_message} onChange={e => setNewTicket({ ...newTicket, initial_message: e.target.value })} />
                    <button className="btn btn-primary" onClick={createTicket} disabled={!newTicket.subject || !newTicket.initial_message}>Enviar Ticket</button>
                </div>
            )}

            {view === 'detail' && selectedTicket && (
                <div className="ticket-detail">
                    <div style={{ padding: '1rem', background: 'rgba(255,255,255,0.05)', borderRadius: '8px', marginBottom: '1rem' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                            <h3>#{selectedTicket.id} - {selectedTicket.subject}</h3>
                            {userRole === 'admin_master' && (
                                <select value={selectedTicket.status} onChange={e => updateStatus(e.target.value)} style={{ width: 'auto' }}>
                                    <option value="open">Abierto</option>
                                    <option value="in_progress">En Progreso</option>
                                    <option value="resolved">Resuelto</option>
                                    <option value="closed">Cerrado</option>
                                </select>
                            )}
                        </div>
                        <div style={{ fontSize: '0.9rem', opacity: 0.7, marginTop: '0.5rem' }}>
                            Por: {selectedTicket.user_email} | {selectedTicket.category} | {selectedTicket.priority}
                        </div>
                    </div>

                    <div className="chat-thread" style={{ maxHeight: '400px', overflowY: 'auto', marginBottom: '1rem' }}>
                        {selectedTicket.messages.map(m => (
                            <div key={m.id} className={`chat-message ${m.is_staff ? 'received' : 'sent'}`} style={{ alignSelf: m.is_staff ? 'flex-start' : 'flex-end', background: m.is_staff ? '#374151' : '#4f46e5' }}>
                                <div style={{ fontWeight: 'bold', fontSize: '0.7rem', marginBottom: '0.2rem' }}>{m.sender_email} <span style={{ fontWeight: 'normal', opacity: 0.6 }}>{new Date(m.created_at).toLocaleString()}</span></div>
                                <div>{m.body}</div>
                            </div>
                        ))}
                    </div>

                    {selectedTicket.status !== 'closed' && (
                        <div style={{ display: 'flex', gap: '0.5rem' }}>
                            <textarea value={replyBody} onChange={e => setReplyBody(e.target.value)} placeholder="Escribir respuesta..." style={{ flex: 1 }} />
                            <button className="btn btn-primary" onClick={sendReply} disabled={!replyBody}><Send size={18} /></button>
                        </div>
                    )}
                </div>
            )}


        </div>
    );
};

const ChatWidget = ({ token, currentUser, plan }) => {
    const [isOpen, setIsOpen] = useState(false);
    const [masterAdmin, setMasterAdmin] = useState(null);
    const [messages, setMessages] = useState([]);
    const [newMessage, setNewMessage] = useState('');
    const [loading, setLoading] = useState(false);

    useEffect(() => {
        if (token) {
            fetch(`${API_BASE}/admin/master-info`, { headers: { 'Authorization': `Bearer ${token}` } })
                .then(res => res.json())
                .then(data => { if (data.id) setMasterAdmin(data); })
                .catch(e => console.error("ChatWidget: no master", e));
        }
    }, [token]);

    useEffect(() => {
        if (isOpen && masterAdmin && token) {
            fetchMessages();
            const interval = setInterval(fetchMessages, 5000);
            return () => clearInterval(interval);
        }
    }, [isOpen, masterAdmin, token]);

    const fetchMessages = async () => {
        if (!masterAdmin || !token) return;
        try {
            const res = await fetch(`${API_BASE}/admin/chat/messages/${masterAdmin.id}`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (res.ok) {
                const data = await res.json();
                setMessages(Array.isArray(data) ? data : []);
            }
        } catch (e) { }
    };

    const sendMessage = async () => {
        if (!newMessage.trim() || !masterAdmin || !token) return;
        setLoading(true);
        try {
            const res = await fetch(`${API_BASE}/admin/chat/send`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
                body: JSON.stringify({ receiver_id: masterAdmin.id, body: newMessage })
            });
            if (res.ok) {
                setNewMessage('');
                fetchMessages();
            }
        } catch (e) { }
        setLoading(false);
    };

    const isMaster = currentUser?.role === 'admin_master';
    if (!token || !currentUser || isMaster) return null;
    if (plan === 'free') return null;

    return (
        <div style={{ position: 'fixed', bottom: '2rem', right: '2rem', zIndex: 9999 }}>
            {!isOpen ? (
                <button
                    onClick={() => setIsOpen(true)}
                    className="btn btn-primary"
                    style={{ borderRadius: '50%', width: '60px', height: '60px', boxShadow: '0 10px 25px rgba(99, 102, 241, 0.4)', padding: 0, display: 'flex', justifyContent: 'center', alignItems: 'center' }}
                >
                    <MessageSquare size={28} />
                </button>
            ) : (
                <div className="glass-card" style={{ width: '350px', height: '450px', display: 'flex', flexDirection: 'column', overflow: 'hidden', boxShadow: '0 20px 40px rgba(0,0,0,0.3)', border: '1px solid var(--primary-color)', borderRadius: '16px' }}>
                    <div style={{ padding: '1rem', background: 'var(--primary-color)', color: 'white', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.8rem' }}>
                            <Shield size={18} />
                            <div>
                                <div style={{ fontWeight: 'bold', fontSize: '0.9rem' }}>Soporte Master</div>
                                <div style={{ fontSize: '0.7rem', opacity: 0.8 }}>En línea ahora</div>
                            </div>
                        </div>
                        <button onClick={() => setIsOpen(false)} style={{ background: 'none', border: 'none', color: 'white', cursor: 'pointer' }}><X size={20} /></button>
                    </div>
                    <div style={{ flex: 1, overflowY: 'auto', padding: '1rem', display: 'flex', flexDirection: 'column', gap: '0.8rem', background: 'var(--bg-app)' }}>
                        {messages.length === 0 && <div style={{ textAlign: 'center', marginTop: '20%', opacity: 0.5, fontSize: '0.8rem' }}>¡Hola! Cuéntanos en qué podemos ayudarte. Escribe tu mensaje y el Administrador Maestro te responderá pronto.</div>}
                        {messages.map(msg => (
                            <div key={msg.id} style={{
                                alignSelf: msg.sender_id === currentUser.id ? 'flex-end' : 'flex-start',
                                background: msg.sender_id === currentUser.id ? 'var(--primary-color)' : 'var(--bg-surface)',
                                color: msg.sender_id === currentUser.id ? 'white' : 'var(--text-main)',
                                padding: '0.6rem 0.8rem',
                                borderRadius: '12px',
                                fontSize: '0.8rem',
                                maxWidth: '85%',
                                border: msg.sender_id === currentUser.id ? 'none' : '1px solid var(--border-color)',
                                boxShadow: '0 2px 5px rgba(0,0,0,0.1)'
                            }}>
                                {msg.body}
                                <div style={{ fontSize: '0.6rem', opacity: 0.5, textAlign: 'right', marginTop: '0.2rem' }}>
                                    {new Date(msg.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                                </div>
                            </div>
                        ))}
                    </div>
                    <div style={{ padding: '1rem', borderTop: '1px solid var(--border-color)', display: 'flex', gap: '0.5rem', background: 'var(--bg-surface)' }}>
                        <input value={newMessage} onChange={e => setNewMessage(e.target.value)} onKeyPress={e => e.key === 'Enter' && sendMessage()} placeholder="Escribe tu mensaje..." style={{ flex: 1, marginBottom: 0, fontSize: '0.8rem' }} />
                        <button onClick={sendMessage} className="btn btn-primary" disabled={loading || !newMessage.trim()} style={{ padding: '0.5rem 1rem' }}><Send size={18} /></button>
                    </div>
                </div>
            )}
        </div>
    );
};

export default App;
