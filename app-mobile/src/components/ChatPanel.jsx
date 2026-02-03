import React, { useState, useEffect } from 'react';
import { MessageSquare, Send, Users, Clock, Check, CheckCheck, ShieldOff, Trash2, X } from 'lucide-react';

const API_BASE = "/api";

const ChatPanel = ({ token, currentUser }) => {
    const [conversations, setConversations] = useState([]);
    const [selectedPartner, setSelectedPartner] = useState(null);
    const [messages, setMessages] = useState([]);
    const [newMessage, setNewMessage] = useState('');
    const [unreadCount, setUnreadCount] = useState(0);
    const [loading, setLoading] = useState(false);

    // Fetch conversations
    const fetchConversations = async () => {
        try {
            const res = await fetch(`${API_BASE}/admin/chat/conversations`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (res.ok) {
                const data = await res.json();
                setConversations(data);
            }
        } catch (err) {
            console.error("Error fetching conversations:", err);
        }
    };

    // Fetch messages with selected partner
    const fetchMessages = async (partnerId) => {
        try {
            const res = await fetch(`${API_BASE}/admin/chat/messages/${partnerId}`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (res.ok) {
                const data = await res.json();
                setMessages(data);
            }
        } catch (err) {
            console.error("Error fetching messages:", err);
        }
    };

    // Fetch unread count
    const fetchUnreadCount = async () => {
        try {
            const res = await fetch(`${API_BASE}/admin/chat/unread-count`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (res.ok) {
                const data = await res.json();
                setUnreadCount(data.unread_count);
            }
        } catch (err) {
            console.error("Error fetching unread count:", err);
        }
    };

    // Send message
    const sendMessage = async () => {
        if (!newMessage.trim() || !selectedPartner) return;

        setLoading(true);
        try {
            const res = await fetch(`${API_BASE}/admin/chat/send`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({
                    receiver_id: selectedPartner.id,
                    body: newMessage
                })
            });

            if (res.ok) {
                setNewMessage('');
                await fetchMessages(selectedPartner.id);
                await fetchConversations();
            }
        } catch (err) {
            console.error("Error sending message:", err);
        } finally {
            setLoading(false);
        }
    };

    // Block user
    const blockUser = async () => {
        if (!selectedPartner) return;
        if (!window.confirm(`¿Seguro que deseas bloquear a ${selectedPartner.username}?`)) return;

        try {
            const res = await fetch(`${API_BASE}/admin/chat/block?blocked_id=${selectedPartner.id}`, {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (res.ok) {
                alert("Usuario bloqueado");
                setSelectedPartner(null);
                fetchConversations();
            }
        } catch (err) { console.error(err); }
    };

    // Delete conversation
    const deleteConversation = async () => {
        if (!selectedPartner) return;
        if (!window.confirm("¿Deseas eliminar el historial con este usuario?")) return;

        try {
            const res = await fetch(`${API_BASE}/admin/chat/conversation/${selectedPartner.id}`, {
                method: 'DELETE',
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (res.ok) {
                setSelectedPartner(null);
                fetchConversations();
            }
        } catch (err) { console.error(err); }
    };

    // Initial load
    useEffect(() => {
        fetchConversations();
        fetchUnreadCount();

        // Auto-refresh every 10 seconds
        const interval = setInterval(() => {
            fetchConversations();
            fetchUnreadCount();
            if (selectedPartner) {
                fetchMessages(selectedPartner.id);
            }
        }, 10000);

        return () => clearInterval(interval);
    }, [selectedPartner]);

    // Load messages when partner selected
    useEffect(() => {
        if (selectedPartner) {
            fetchMessages(selectedPartner.id);
        }
    }, [selectedPartner]);

    const formatTime = (isoString) => {
        const date = new Date(isoString);
        const now = new Date();
        const diff = now - date;
        const hours = Math.floor(diff / (1000 * 60 * 60));

        if (hours < 1) {
            const minutes = Math.floor(diff / (1000 * 60));
            return `Hace ${minutes}m`;
        } else if (hours < 24) {
            return `Hace ${hours}h`;
        } else {
            return date.toLocaleDateString();
        }
    };

    return (
        <div style={{ display: 'grid', gridTemplateColumns: '350px 1fr', gap: '1.5rem', height: '70vh' }}>
            {/* Conversations List */}
            <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
                <div style={{ padding: '1rem', borderBottom: '1px solid var(--border-color)' }}>
                    <h3 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <Users size={20} />
                        Conversaciones
                        {unreadCount > 0 && (
                            <span style={{
                                background: '#ef4444',
                                color: 'white',
                                borderRadius: '12px',
                                padding: '2px 8px',
                                fontSize: '0.75rem',
                                fontWeight: 'bold'
                            }}>
                                {unreadCount}
                            </span>
                        )}
                    </h3>
                </div>
                <div style={{ flex: 1, overflowY: 'auto' }}>
                    {conversations.length === 0 ? (
                        <div style={{ padding: '2rem', textAlign: 'center', opacity: 0.5 }}>
                            <MessageSquare size={48} style={{ margin: '0 auto 1rem' }} />
                            <p>No hay conversaciones</p>
                        </div>
                    ) : (
                        conversations.map(conv => (
                            <div
                                key={conv.partner.id}
                                onClick={() => setSelectedPartner(conv.partner)}
                                style={{
                                    padding: '1rem',
                                    borderBottom: '1px solid var(--border-color)',
                                    cursor: 'pointer',
                                    background: selectedPartner?.id === conv.partner.id ? 'rgba(99, 102, 241, 0.1)' : 'transparent',
                                    transition: 'background 0.2s'
                                }}
                            >
                                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
                                    <div style={{ fontWeight: 'bold', fontSize: '0.9rem' }}>
                                        {conv.partner.username}
                                    </div>
                                    <div style={{ fontSize: '0.7rem', opacity: 0.6 }}>
                                        {formatTime(conv.last_message_at)}
                                    </div>
                                </div>
                                <div style={{ fontSize: '0.8rem', opacity: 0.7, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                    {conv.last_message}
                                </div>
                                {conv.unread_count > 0 && (
                                    <div style={{
                                        marginTop: '0.5rem',
                                        background: '#6366f1',
                                        color: 'white',
                                        borderRadius: '10px',
                                        padding: '2px 6px',
                                        fontSize: '0.7rem',
                                        display: 'inline-block'
                                    }}>
                                        {conv.unread_count} nuevo{conv.unread_count > 1 ? 's' : ''}
                                    </div>
                                )}
                            </div>
                        ))
                    )}
                </div>
            </div>

            {/* Messages View */}
            <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
                {selectedPartner ? (
                    <>
                        <div style={{ padding: '1rem', borderBottom: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <div>
                                <h3 style={{ margin: 0 }}>{selectedPartner.username}</h3>
                                <div style={{ fontSize: '0.75rem', opacity: 0.6, marginTop: '0.25rem' }}>
                                    {selectedPartner.role === 'admin_master' ? 'Administrador Master' :
                                        selectedPartner.role === 'admin_empresa' ? 'Admin Empresa' : 'Operador'}
                                </div>
                            </div>
                            <div style={{ display: 'flex', gap: '0.5rem' }}>
                                <button className="action-btn suspend" onClick={blockUser} title="Bloquear Usuario"><ShieldOff size={18} /></button>
                                <button className="action-btn delete" onClick={deleteConversation} title="Eliminar Conversación"><Trash2 size={18} /></button>
                                <button className="action-btn" onClick={() => setSelectedPartner(null)} title="Cerrar"><X size={18} /></button>
                            </div>
                        </div>

                        <div style={{ flex: 1, overflowY: 'auto', padding: '1rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                            {messages.map(msg => {
                                const isSent = msg.sender_id === currentUser.id;
                                return (
                                    <div
                                        key={msg.id}
                                        style={{
                                            alignSelf: isSent ? 'flex-end' : 'flex-start',
                                            maxWidth: '70%'
                                        }}
                                    >
                                        <div
                                            style={{
                                                background: isSent ? '#6366f1' : 'var(--bg-surface)',
                                                color: isSent ? 'white' : 'var(--text-main)',
                                                padding: '0.75rem 1rem',
                                                borderRadius: '12px',
                                                border: isSent ? 'none' : '1px solid var(--border-color)'
                                            }}
                                        >
                                            {msg.body}
                                        </div>
                                        <div style={{
                                            fontSize: '0.7rem',
                                            opacity: 0.5,
                                            marginTop: '0.25rem',
                                            textAlign: isSent ? 'right' : 'left',
                                            display: 'flex',
                                            alignItems: 'center',
                                            gap: '0.25rem',
                                            justifyContent: isSent ? 'flex-end' : 'flex-start'
                                        }}>
                                            <Clock size={10} />
                                            {new Date(msg.created_at).toLocaleTimeString('es-ES', { hour: '2-digit', minute: '2-digit' })}
                                            {isSent && (msg.is_read ? <CheckCheck size={12} color="#10b981" /> : <Check size={12} />)}
                                        </div>
                                    </div>
                                );
                            })}
                        </div>

                        <div style={{ padding: '1rem', borderTop: '1px solid var(--border-color)' }}>
                            <div style={{ display: 'flex', gap: '0.5rem' }}>
                                <input
                                    type="text"
                                    value={newMessage}
                                    onChange={e => setNewMessage(e.target.value)}
                                    onKeyPress={e => e.key === 'Enter' && sendMessage()}
                                    placeholder="Escribe un mensaje..."
                                    style={{ flex: 1, marginBottom: 0 }}
                                    disabled={loading}
                                />
                                <button
                                    onClick={sendMessage}
                                    className="btn btn-primary"
                                    disabled={loading || !newMessage.trim()}
                                    style={{ padding: '0.6rem 1.5rem' }}
                                >
                                    <Send size={18} />
                                </button>
                            </div>
                        </div>
                    </>
                ) : (
                    <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', opacity: 0.5 }}>
                        <div style={{ textAlign: 'center' }}>
                            <MessageSquare size={64} style={{ margin: '0 auto 1rem' }} />
                            <p>Selecciona una conversación para comenzar</p>
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
};

export default ChatPanel;
