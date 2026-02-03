import React, { useState, useEffect, useCallback } from 'react';
import {
    Home, Building, Monitor, User, Menu, LogOut,
    ChevronRight, Plus, Search, X, CheckCircle, AlertCircle, Wifi, WifiOff
} from 'lucide-react';
import './index.css';

const API_BASE = localStorage.getItem('server_url') || 'http://192.168.1.182:8000';

const MobileApp = ({ token, userObj, onLogout }) => {
    // Derived State
    const role = userObj?.role || 'client';

    const [view, setView] = useState(role === 'admin_empresa' ? 'content' : 'home');
    const [myCompany, setMyCompany] = useState(null);
    const isSuperAdmin = userObj?.is_admin || role === 'admin_master';
    const companyId = userObj?.company_id;

    // Initial Fetch
    useEffect(() => {
        if (isSuperAdmin) {
            // Future: Implement Super Admin Logic if needed, for now focus on Client
        } else if (companyId) {
            fetchClientData();
        }
    }, [companyId]);

    const fetchClientData = async () => {
        try {
            // 1. Get Company Details
            const compRes = await fetch(`${API_BASE}/companies/${companyId}`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (compRes.ok) setMyCompany(await compRes.json());

            // 2. Get Devices
            const devRes = await fetch(`${API_BASE}/admin/companies/${companyId}/devices`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (devRes.ok) setMyDevices(await devRes.json());

        } catch (e) {
            console.error("Error fetching client data", e);
        }
    };

    return (
        <div className="mobile-app-container">
            {/* CONTENT */}
            <div className="mobile-content">
                {view === 'home' && <ClientHome company={myCompany} devices={myDevices} />}
                {view === 'content' && <MobileContent company={myCompany} user={userObj} token={token} />}
                {view === 'devices' && <ClientDevices devices={myDevices} token={token} refresh={fetchClientData} />}
                {view === 'profile' && <MobileProfile user={userObj} company={myCompany} onLogout={onLogout} />}
            </div>

            {/* NAV BAR */}
            <div className="bottom-nav">
                <NavBtn id="home" icon={Home} label="Inicio" active={view} setView={setView} />
                <NavBtn id="content" icon={Monitor} label="Contenido" active={view} setView={setView} />
                <NavBtn id="devices" icon={Wifi} label="Pantallas" active={view} setView={setView} />
                <NavBtn id="profile" icon={User} label="Perfil" active={view} setView={setView} />
            </div>
        </div>
    );
};

const NavBtn = ({ id, icon: Icon, label, active, setView }) => (
    <button
        className={`nav-item ${active === id ? 'active' : ''}`}
        onClick={() => setView(id)}
    >
        <Icon size={24} />
        <span>{label}</span>
    </button>
);

// --- CLIENT VIEWS ---

const ClientHome = ({ company, devices }) => {
    if (!company) return <div className="p-4">Cargando...</div>;

    const onlineCount = devices.filter(d => d.is_online).length;
    const offlineCount = devices.length - onlineCount;

    return (
        <div className="mobile-view p-4">
            <h1 className="text-xl font-bold mb-1">Mi Panel</h1>
            <p className="opacity-60 mb-6 text-sm">{company.name}</p>

            <div className="stats-grid-mobile">
                <div className="stat-card">
                    <span className="label">Plan</span>
                    <span className="value" style={{ fontSize: '1.2rem', textTransform: 'uppercase' }}>{company.plan}</span>
                </div>
                <div className="stat-card">
                    <span className="label">Vencimiento</span>
                    <span className="value" style={{ fontSize: '1rem' }}>{new Date(company.valid_until).toLocaleDateString()}</span>
                </div>
            </div>

            <div className="mt-4 p-4 rounded-xl bg-[rgba(255,255,255,0.05)] border border-[rgba(255,255,255,0.1)]">
                <div className="flex justify-between items-center mb-4">
                    <h3 className="font-bold">Estado de Pantallas</h3>
                    <span className="text-sm opacity-50">{devices.length} Total</span>
                </div>
                <div className="flex gap-4">
                    <div className="flex-1 p-3 bg-green-900/20 rounded-lg flex items-center gap-3">
                        <Wifi size={20} className="text-green-500" />
                        <div>
                            <div className="font-bold text-lg">{onlineCount}</div>
                            <div className="text-xs opacity-60">En Línea</div>
                        </div>
                    </div>
                    <div className="flex-1 p-3 bg-red-900/20 rounded-lg flex items-center gap-3">
                        <WifiOff size={20} className="text-red-500" />
                        <div>
                            <div className="font-bold text-lg">{offlineCount}</div>
                            <div className="text-xs opacity-60">Offline</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

const ClientDevices = ({ devices, token, refresh }) => {
    const [selectedDevice, setSelectedDevice] = useState(null);
    const [action, setAction] = useState(null); // 'menu', 'rename', 'delete_confirm'
    const [newName, setNewName] = useState('');

    const handleAction = (device) => {
        setSelectedDevice(device);
        setAction('menu');
    };

    const handleRename = async () => {
        if (!newName.trim()) return;
        try {
            await fetch(`${API_BASE}/admin/devices/${selectedDevice.uuid}`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
                body: JSON.stringify({ name: newName })
            });
            setAction(null);
            refresh();
        } catch (e) { alert("Error: " + e.message); }
    };

    const handleToggle = async () => {
        try {
            await fetch(`${API_BASE}/admin/devices/${selectedDevice.uuid}/status?is_active=${!selectedDevice.is_active}`, {
                method: 'PATCH',
                headers: { 'Authorization': `Bearer ${token}` }
            });
            setAction(null);
            refresh();
        } catch (e) { alert("Error"); }
    };

    const handleDelete = async () => {
        try {
            await fetch(`${API_BASE}/admin/devices/${selectedDevice.uuid}`, {
                method: 'DELETE',
                headers: { 'Authorization': `Bearer ${token}` }
            });
            setAction(null);
            refresh();
        } catch (e) { alert("Error"); }
    };

    return (
        <div className="mobile-view relative">
            <div className="view-header p-4 border-b border-gray-800 flex justify-between items-center">
                <h2 className="text-lg font-bold">Mis Pantallas</h2>
                <button onClick={refresh} className="text-sm text-blue-400">Actualizar</button>
            </div>

            <div className="list-container pb-24">
                {devices.map(d => (
                    <div key={d.uuid} className="list-item" onClick={() => handleAction(d)}>
                        <div className={`item-icon ${d.is_online ? 'bg-green-900/40 text-green-400' : 'bg-red-900/40 text-red-400'}`}>
                            <Monitor size={20} />
                        </div>
                        <div className="item-info">
                            <div className="item-title">{d.name}</div>
                            <div className="item-subtitle font-mono text-xs opacity-50">{d.uuid.substring(0, 8)}...</div>
                        </div>
                        <div className="flex flex-col items-end gap-1">
                            <span className={`text-xs px-2 py-0.5 rounded-full ${d.is_active ? 'bg-green-500/20 text-green-400' : 'bg-yellow-500/20 text-yellow-400'}`}>
                                {d.is_active ? 'Activa' : 'Pausada'}
                            </span>
                            <Menu size={16} className="text-gray-500 mt-1" />
                        </div>
                    </div>
                ))}
                {devices.length === 0 && (
                    <div className="p-8 text-center opacity-50">
                        <Monitor size={48} className="mx-auto mb-4 opacity-20" />
                        <p>No tienes pantallas vinculadas</p>
                    </div>
                )}
            </div>

            {/* ACTION SHEET / MODAL SIMULATION */}
            {action === 'menu' && (
                <div className="fixed inset-0 z-50 flex items-end bg-black/80" onClick={() => setAction(null)}>
                    <div className="w-full bg-[#1e293b] rounded-t-2xl p-4 animate-slide-up" onClick={e => e.stopPropagation()}>
                        <div className="flex justify-between items-center mb-4 border-b border-white/10 pb-2">
                            <h3 className="font-bold text-lg">{selectedDevice.name}</h3>
                            <button onClick={() => setAction(null)}><X size={20} /></button>
                        </div>

                        <div className="flex flex-col gap-2">
                            <button onClick={() => { setNewName(selectedDevice.name); setAction('rename'); }} className="p-4 bg-white/5 rounded-xl flex items-center gap-3 font-bold">
                                <Menu size={20} /> Renombrar
                            </button>
                            <button onClick={handleToggle} className="p-4 bg-white/5 rounded-xl flex items-center gap-3 font-bold">
                                {selectedDevice.is_active ? <WifiOff size={20} className="text-yellow-500" /> : <Wifi size={20} className="text-green-500" />}
                                {selectedDevice.is_active ? 'Suspender Pantalla' : 'Reactivar Pantalla'}
                            </button>
                            <button onClick={() => setAction('delete_confirm')} className="p-4 bg-red-500/10 text-red-500 rounded-xl flex items-center gap-3 font-bold mt-2">
                                <LogOut size={20} /> Desvincular Permanenetemente
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {action === 'rename' && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/90 p-4">
                    <div className="bg-[#1e293b] w-full rounded-2xl p-6">
                        <h3 className="font-bold mb-4">Renombrar Pantalla</h3>
                        <input
                            value={newName}
                            onChange={e => setNewName(e.target.value)}
                            className="w-full p-3 bg-black/30 rounded-lg border border-white/10 text-white mb-4"
                            autoFocus
                        />
                        <div className="flex gap-2">
                            <button onClick={() => setAction(null)} className="flex-1 p-3 rounded-lg bg-white/10">Cancelar</button>
                            <button onClick={handleRename} className="flex-1 p-3 rounded-lg bg-blue-600 font-bold">Guardar</button>
                        </div>
                    </div>
                </div>
            )}

            {action === 'delete_confirm' && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/90 p-4">
                    <div className="bg-[#1e293b] w-full rounded-2xl p-6 border border-red-500/30">
                        <AlertCircle size={48} className="text-red-500 mx-auto mb-4" />
                        <h3 className="font-bold text-center text-xl mb-2">¿Estás seguro?</h3>
                        <p className="text-center opacity-70 mb-6">Esta acción eliminará la pantalla. Tendrás que volver a vincularla físicamente.</p>
                        <div className="flex gap-2">
                            <button onClick={() => setAction(null)} className="flex-1 p-3 rounded-lg bg-white/10">Cancelar</button>
                            <button onClick={handleDelete} className="flex-1 p-3 rounded-lg bg-red-600 font-bold">Sí, Eliminar</button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

const MobileContent = ({ user, company, token }) => {
    const [tab, setTab] = useState('center'); // center, side, bottom
    const [isSaving, setIsSaving] = useState(false);

    const isOperator = user?.role === 'operador_empresa';

    // Center logic
    const [playlist, setPlaylist] = useState(['', '', '']);
    const [driveVideo, setDriveVideo] = useState('');
    const [videoSource, setVideoSource] = useState('youtube');
    const [adFreq, setAdFreq] = useState(3);

    // Sidebar logic
    const [sidebarContent, setSidebarContent] = useState([]);
    const [selectedBlock, setSelectedBlock] = useState(0);

    // Bottom logic
    const [ticker, setTicker] = useState('');
    const [staticMsg, setStaticMsg] = useState('');
    const [socials, setSocials] = useState({ whatsapp: '', instagram: '' });

    useEffect(() => {
        if (company) {
            setPlaylist(Array.isArray(company.video_playlist) ? company.video_playlist.slice(0, 3) : ['', '', '']);
            setDriveVideo(company.google_drive_link || '');
            setVideoSource(company.video_source || 'youtube');
            setAdFreq(company.ad_frequency || 3);
            setSidebarContent(Array.isArray(company.sidebar_content) ? company.sidebar_content : []);

            const msgs = company.bottom_bar_content?.messages || [];
            if (msgs.length > 0) setTicker(msgs[0]);
            setStaticMsg(company.bottom_bar_content?.static || '');
            setSocials({
                whatsapp: company.bottom_bar_content?.whatsapp || '',
                instagram: company.bottom_bar_content?.instagram || ''
            });
        }
    }, [company]);

    const handleSave = async () => {
        setIsSaving(true);
        try {
            const payload = {
                video_source: videoSource,
                priority_content_url: playlist[0],
                video_playlist: playlist,
                google_drive_link: driveVideo,
                ad_frequency: adFreq,
                sidebar_content: sidebarContent,
                bottom_bar_content: {
                    ...company.bottom_bar_content,
                    static: staticMsg,
                    messages: [ticker],
                    whatsapp: socials.whatsapp,
                    instagram: socials.instagram
                }
            };

            const res = await fetch(`${API_BASE}/companies/${company.id}`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
                body: JSON.stringify(payload)
            });

            if (res.ok) alert("Contenido actualizado en todas las pantallas");
            else alert("Error al guardar");

        } catch (e) {
            console.error(e);
            alert("Error de conexión");
        }
        setIsSaving(false);
    };

    const updateSidebarBlock = (idx, field, value) => {
        const next = [...sidebarContent];
        while (next.length <= idx) next.push({ type: 'image', value: '' });
        next[idx] = { ...next[idx], [field]: value };
        setSidebarContent(next);
    };

    const currentBlock = sidebarContent[selectedBlock] || { type: 'image', value: '' };

    return (
        <div className="mobile-view p-4 pb-32">
            <h2 className="text-lg font-bold mb-4">Gestionar Contenido</h2>

            <div className="flex bg-[#0f172a] p-1 rounded-xl mb-6">
                <button onClick={() => setTab('center')} className={`flex-1 py-2 text-sm font-bold rounded-lg transition-all ${tab === 'center' ? 'bg-blue-600 shadow-lg text-white' : 'text-white/40'}`}>Videos</button>
                <button onClick={() => setTab('side')} className={`flex-1 py-2 text-sm font-bold rounded-lg transition-all ${tab === 'side' ? 'bg-purple-600 shadow-lg text-white' : 'text-white/40'}`}>Lateral</button>
                <button onClick={() => setTab('bottom')} className={`flex-1 py-2 text-sm font-bold rounded-lg transition-all ${tab === 'bottom' ? 'bg-green-600 shadow-lg text-white' : 'text-white/40'}`}>Inferior</button>
            </div>

            {isOperator && (
                <div className="mb-4 p-3 bg-yellow-500/10 border border-yellow-500/20 rounded-lg flex items-center gap-2">
                    <AlertCircle size={16} className="text-yellow-500" />
                    <span className="text-xs text-yellow-500/80">Modo Operador: Solo puede modificar la Playlist.</span>
                </div>
            )}

            {tab === 'center' && (
                <div className="animate-fade-in">
                    <div className="flex bg-black/30 rounded-lg p-1 mb-4 border border-white/10">
                        <button
                            onClick={() => setVideoSource('youtube')}
                            className={`flex-1 py-2 text-xs font-bold rounded-md transition-all ${videoSource === 'youtube' ? 'bg-blue-600 text-white' : 'text-white/40'}`}
                        >
                            YouTube
                        </button>
                        <button
                            onClick={() => setVideoSource('drive')}
                            className={`flex-1 py-2 text-xs font-bold rounded-md transition-all ${videoSource === 'drive' ? 'bg-green-600 text-white' : 'text-white/40'}`}
                        >
                            Google Drive
                        </button>
                    </div>

                    <div className={`bg-blue-900/10 border border-blue-500/20 p-4 rounded-xl mb-4 transition-all ${videoSource !== 'youtube' ? 'opacity-50 grayscale' : ''}`}>
                        <h3 className="flex items-center gap-2 font-bold text-blue-400 mb-4"><Monitor size={18} /> Playlist YouTube</h3>
                        {playlist.map((url, i) => (
                            <div key={i} className="mb-3">
                                <label className="text-xs opacity-50 block mb-1">Video {i + 1}</label>
                                <input
                                    className="w-full bg-black/30 border border-white/10 rounded-lg p-3 text-sm"
                                    placeholder="https://youtube.com/..."
                                    value={url}
                                    onChange={e => {
                                        const next = [...playlist];
                                        next[i] = e.target.value;
                                        setPlaylist(next);
                                    }}
                                />
                            </div>
                        ))}
                    </div>

                    <div className="bg-white/5 border border-white/10 p-4 rounded-xl">
                        <h3 className="font-bold mb-4 text-sm opacity-80">Configuración Ads</h3>
                        <div className="mb-4">
                            <label className="text-xs opacity-50 block mb-1">Frecuencia (Cada X videos)</label>
                            <input
                                type="number"
                                disabled={isOperator}
                                className={`w-full bg-black/30 border border-white/10 rounded-lg p-3 text-sm ${isOperator ? 'opacity-50 cursor-not-allowed' : ''}`}
                                value={adFreq}
                                onChange={e => setAdFreq(parseInt(e.target.value))}
                            />
                        </div>
                        <div className={`transition-all ${videoSource !== 'drive' ? 'opacity-50' : ''}`}>
                            <label className="text-xs opacity-50 block mb-1">Video Drive (Intersticial)</label>
                            <input
                                disabled={isOperator}
                                className={`w-full bg-black/30 border border-white/10 rounded-lg p-3 text-sm ${isOperator ? 'opacity-50 cursor-not-allowed' : ''}`}
                                placeholder="Link de Drive..."
                                value={driveVideo}
                                onChange={e => setDriveVideo(e.target.value)}
                            />
                        </div>
                    </div>
                </div>
            )}

            {tab === 'side' && (
                <div className="animate-fade-in">
                    <div className="flex gap-2 mb-4 overflow-x-auto pb-2">
                        {[0, 1, 2].map(i => (
                            <button
                                key={i}
                                onClick={() => setSelectedBlock(i)}
                                className={`px-4 py-2 rounded-lg text-xs font-bold whitespace-nowrap border ${selectedBlock === i ? 'bg-purple-600 border-purple-400 text-white' : 'bg-transparent border-white/10 text-white/50'}`}
                            >
                                Bloque {i + 1}
                            </button>
                        ))}
                    </div>

                    <div className="bg-purple-900/10 border border-purple-500/20 p-4 rounded-xl">
                        <div className="flex justify-between items-center mb-4">
                            <h3 className="font-bold text-purple-400">Bloque {selectedBlock + 1}</h3>
                            <div className="flex bg-black/40 rounded-lg p-1">
                                <button
                                    disabled={isOperator}
                                    onClick={() => updateSidebarBlock(selectedBlock, 'type', 'image')}
                                    className={`px-3 py-1 text-xs rounded-md ${currentBlock.type === 'image' ? 'bg-purple-500 text-white' : 'opacity-50'} ${isOperator ? 'cursor-not-allowed' : ''}`}
                                >Imagen</button>
                                <button
                                    disabled={isOperator}
                                    onClick={() => updateSidebarBlock(selectedBlock, 'type', 'text')}
                                    className={`px-3 py-1 text-xs rounded-md ${currentBlock.type === 'text' ? 'bg-purple-500 text-white' : 'opacity-50'} ${isOperator ? 'cursor-not-allowed' : ''}`}
                                >Texto</button>
                            </div>
                        </div>

                        {currentBlock.type === 'image' ? (
                            <div>
                                <label className="text-xs opacity-50 block mb-1">URL Imagen (Drive/Web)</label>
                                <textarea
                                    disabled={isOperator}
                                    className={`w-full bg-black/30 border border-white/10 rounded-lg p-3 text-sm font-mono h-24 ${isOperator ? 'opacity-50 cursor-not-allowed' : ''}`}
                                    placeholder="https://drive.google.com/..."
                                    value={currentBlock.value || ''}
                                    onChange={e => updateSidebarBlock(selectedBlock, 'value', e.target.value)}
                                />
                                {!isOperator && <p className="text-[10px] opacity-40 mt-2">Pega el enlace de la imagen que deseas mostrar en este bloque.</p>}
                            </div>
                        ) : (
                            <div>
                                <label className="text-xs opacity-50 block mb-1">Contenido de Texto</label>
                                <textarea
                                    disabled={isOperator}
                                    className={`w-full bg-black/30 border border-white/10 rounded-lg p-3 text-sm h-24 ${isOperator ? 'opacity-50 cursor-not-allowed' : ''}`}
                                    placeholder="Escribe tu promoción aquí..."
                                    value={currentBlock.value || ''}
                                    onChange={e => updateSidebarBlock(selectedBlock, 'value', e.target.value)}
                                />
                            </div>
                        )}
                    </div>
                </div>
            )}

            {tab === 'bottom' && (
                <div className="animate-fade-in">
                    <div className="bg-green-900/10 border border-green-500/20 p-4 rounded-xl mb-4">
                        <h3 className="font-bold text-green-400 mb-4">Cintillo Rotativo</h3>
                        <textarea
                            disabled={isOperator}
                            className={`w-full bg-black/30 border border-white/10 rounded-lg p-3 text-sm h-24 ${isOperator ? 'opacity-50 cursor-not-allowed' : ''}`}
                            placeholder="Mensaje que se desplaza..."
                            value={ticker}
                            onChange={e => setTicker(e.target.value)}
                        />
                    </div>

                    <div className="bg-white/5 border border-white/10 p-4 rounded-xl">
                        <div className="mb-4">
                            <label className="text-xs opacity-50 block mb-1">Mensaje Estático (Fijo)</label>
                            <input
                                disabled={isOperator}
                                className={`w-full bg-black/30 border border-white/10 rounded-lg p-3 text-sm ${isOperator ? 'opacity-50 cursor-not-allowed' : ''}`}
                                value={staticMsg}
                                onChange={e => setStaticMsg(e.target.value)}
                                placeholder="Ej: Bienvenidos"
                            />
                        </div>
                        <div className="grid grid-cols-2 gap-3">
                            <div>
                                <label className="text-xs opacity-50 block mb-1">WhatsApp</label>
                                <input
                                    disabled={isOperator}
                                    className={`w-full bg-black/30 border border-white/10 rounded-lg p-3 text-sm ${isOperator ? 'opacity-50 cursor-not-allowed' : ''}`}
                                    value={socials.whatsapp}
                                    onChange={e => setSocials({ ...socials, whatsapp: e.target.value })}
                                    placeholder="+58..."
                                />
                            </div>
                            <div>
                                <label className="text-xs opacity-50 block mb-1">Instagram</label>
                                <input
                                    disabled={isOperator}
                                    className={`w-full bg-black/30 border border-white/10 rounded-lg p-3 text-sm ${isOperator ? 'opacity-50 cursor-not-allowed' : ''}`}
                                    value={socials.instagram}
                                    onChange={e => setSocials({ ...socials, instagram: e.target.value })}
                                    placeholder="@..."
                                />
                            </div>
                        </div>
                    </div>
                </div>
            )}

            <button
                onClick={handleSave}
                disabled={isSaving}
                className="btn-block primary fixed bottom-24 left-4 right-4 shadow-xl z-20"
                style={{ width: 'calc(100% - 2rem)' }}
            >
                {isSaving ? 'Guardando...' : 'Publicar Todo'}
            </button>
        </div>
    );
};

const MobileProfile = ({ user, company, onLogout }) => {
    const [isConfigOpen, setIsConfigOpen] = useState(false);
    const [color, setColor] = useState(company?.primary_color || '#3b82f6');
    const [name, setName] = useState(company?.name || '');

    useEffect(() => {
        if (company) {
            setColor(company.primary_color || '#3b82f6');
            setName(company.name || '');
        }
    }, [company]);

    const handleSaveConfig = async () => {
        try {
            const res = await fetch(`${API_BASE}/companies/${company.id}`, {
                method: 'PATCH',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${user.token || localStorage.getItem('token')}`
                },
                body: JSON.stringify({
                    primary_color: color
                })
            });
            if (res.ok) {
                alert("Diseño actualizado correctamente");
                setIsConfigOpen(false);
                // In a perfect world we would trigger a refresh up chain, but for now this persists
            } else {
                alert("Error al guardar");
            }
        } catch (e) {
            console.error(e);
            alert("Error de conexión");
        }
    };

    return (
        <div className="mobile-view p-4">
            <h2 className="text-lg font-bold mb-6">Mi Perfil</h2>

            <div className="profile-card mb-6">
                <div className="avatar large" style={{ background: color }}>{user?.username?.[0]?.toUpperCase()}</div>
                <div className="text-center mt-4">
                    <div className="font-bold text-xl">{user?.username}</div>
                    <div className="text-sm opacity-60">{user?.role === 'admin_empresa' ? 'Administrador' : 'Operador'}</div>
                </div>
                {company && (
                    <div className="mt-4 pt-4 border-t border-white/10 w-full">
                        <div className="text-center mb-4">
                            <div className="text-sm text-blue-400 font-bold">{company.name}</div>
                            <div className="text-xs opacity-50">ID: {company.id}</div>
                        </div>
                    </div>
                )}
            </div>

            {/* Configuration Actions */}
            <div className="flex flex-col gap-3 mb-6">
                <button className="p-4 bg-[rgba(255,255,255,0.05)] rounded-xl flex items-center justify-between" onClick={() => window.open(`${API_BASE}/tv/${company.uuid_playlist}`, '_blank')}>
                    <div className="flex items-center gap-3">
                        <Monitor size={20} className="text-purple-400" />
                        <span>Ver mi Canal de TV</span>
                    </div>
                    <ChevronRight size={16} className="opacity-50" />
                </button>

                {user.role === 'admin_empresa' && (
                    <button className="p-4 bg-[rgba(255,255,255,0.05)] rounded-xl flex items-center justify-between" onClick={() => setIsConfigOpen(true)}>
                        <div className="flex items-center gap-3">
                            <Building size={20} style={{ color: color }} />
                            <span>Configurar Diseño UI</span>
                        </div>
                        <ChevronRight size={16} className="opacity-50" />
                    </button>
                )}
            </div>

            <button className="btn-block danger mt-auto" onClick={onLogout}>
                <LogOut size={20} /> Cerrar Sesión
            </button>

            <div className="mt-8 text-center text-xs opacity-30">
                VenridesScreenS Mobile v2.2
            </div>

            {/* Config Modal */}
            {isConfigOpen && (
                <div className="fixed inset-0 z-50 flex items-end bg-black/80" onClick={() => setIsConfigOpen(false)}>
                    <div className="w-full bg-[#1e293b] rounded-t-2xl p-6 animate-slide-up" onClick={e => e.stopPropagation()}>
                        <div className="flex justify-between items-center mb-6 border-b border-white/10 pb-2">
                            <h3 className="font-bold text-lg">Personalizar Diseño</h3>
                            <button onClick={() => setIsConfigOpen(false)}><X size={20} /></button>
                        </div>

                        <div className="mb-4">
                            <label className="block text-sm opacity-70 mb-2">Nombre de Empresa (Solo Lectura)</label>
                            <input
                                value={name}
                                readOnly
                                className="w-full p-3 bg-black/30 rounded-lg border border-white/5 text-white/50 cursor-not-allowed"
                            />
                            <p className="text-xs opacity-40 mt-1">Contacte al Master para cambios de nombre/branding mayor.</p>
                        </div>

                        <div className="mb-8">
                            <label className="block text-sm opacity-70 mb-2">Color Corporativo</label>
                            <div className="flex gap-3 overflow-x-auto pb-2">
                                {['#3b82f6', '#ef4444', '#10b981', '#f59e0b', '#8b5cf6', '#ec4899', '#000000'].map(c => (
                                    <button
                                        key={c}
                                        onClick={() => setColor(c)}
                                        className={`w-12 h-12 rounded-full border-2 ${color === c ? 'border-white scale-110' : 'border-transparent'}`}
                                        style={{ background: c }}
                                    />
                                ))}
                            </div>
                        </div>

                        <button onClick={handleSaveConfig} className="w-full p-4 rounded-xl font-bold text-white shadow-lg" style={{ background: color }}>
                            Guardar Cambios
                        </button>
                    </div>
                </div>
            )}
        </div>
    );
};

export default MobileApp;
