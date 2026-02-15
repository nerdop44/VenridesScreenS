import React, { useState, useRef, useEffect } from 'react';

const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

const BenryChat = ({ onOpenContact }) => {
    const [isOpen, setIsOpen] = useState(false);
    const [messages, setMessages] = useState([]);
    const [input, setInput] = useState('');
    const [isTyping, setIsTyping] = useState(false);
    const [sessionId, setSessionId] = useState(null);
    const messagesEndRef = useRef(null);

    // Initialize with welcome message
    useEffect(() => {
        if (isOpen && messages.length === 0) {
            setMessages([{
                role: 'assistant',
                content: '¡Hola! 👋 Soy **Benry**, tu asistente de VenridesScreenS.\n\n¿En qué puedo ayudarte hoy?',
                timestamp: new Date()
            }]);
        }
    }, [isOpen]);

    // Auto-scroll to bottom
    useEffect(() => {
        messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [messages, isTyping]);

    const sendMessage = async (text) => {
        if (!text.trim()) return;

        const userMsg = { role: 'user', content: text, timestamp: new Date() };
        setMessages(prev => [...prev, userMsg]);
        setInput('');
        setIsTyping(true);

        try {
            const res = await fetch(`${API_BASE}/api/benry/chat`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    message: text,
                    session_id: sessionId
                })
            });

            const data = await res.json();

            // Store session ID
            if (data.session_id && !sessionId) {
                setSessionId(data.session_id);
            }

            const aiMsg = {
                role: 'assistant',
                content: data.response,
                timestamp: new Date(),
                needsHandoff: data.needs_handoff,
                leadType: data.lead_type
            };

            setMessages(prev => [...prev, aiMsg]);

            // If handoff needed, show a special message
            if (data.needs_handoff) {
                setTimeout(() => {
                    setMessages(prev => [...prev, {
                        role: 'system',
                        content: '🔔 Un asesor humano ha sido notificado y se pondrá en contacto contigo pronto.',
                        timestamp: new Date()
                    }]);
                }, 1000);
            }
        } catch (err) {
            console.error('Benry chat error:', err);
            setMessages(prev => [...prev, {
                role: 'assistant',
                content: 'Disculpa, estoy teniendo problemas de conexión. Puedes contactarnos directamente en **info.venridesscreen@gmail.com** 📧',
                timestamp: new Date()
            }]);
        } finally {
            setIsTyping(false);
        }
    };

    const handleQuickAction = (action) => {
        switch (action) {
            case 'free':
                sendMessage('Quiero comenzar con el plan gratuito');
                break;
            case 'demo':
                sendMessage('Me gustaría agendar una demo');
                break;
            case 'support':
                sendMessage('Necesito soporte técnico');
                break;
            case 'plans':
                sendMessage('¿Cuáles son los planes y precios disponibles?');
                break;
        }
    };

    const handleSubmit = (e) => {
        e.preventDefault();
        sendMessage(input);
    };

    const renderMessage = (msg, idx) => {
        if (msg.role === 'system') {
            return (
                <div key={idx} className="flex justify-center my-3">
                    <div className="bg-primary/20 border border-primary/40 rounded-xl px-4 py-2 text-sm text-primary max-w-[90%] text-center">
                        {msg.content}
                    </div>
                </div>
            );
        }

        const isUser = msg.role === 'user';
        return (
            <div key={idx} className={`flex ${isUser ? 'justify-end' : 'justify-start'} mb-3`}>
                {!isUser && (
                    <div className="w-7 h-7 rounded-full bg-primary flex items-center justify-center mr-2 mt-1 flex-shrink-0">
                        <span className="text-black text-xs font-bold">B</span>
                    </div>
                )}
                <div className={`max-w-[80%] px-4 py-3 rounded-2xl text-sm leading-relaxed ${isUser
                        ? 'bg-primary text-black rounded-br-md'
                        : 'bg-white/10 text-white rounded-bl-md'
                    }`} style={{ whiteSpace: 'pre-wrap' }}>
                    {msg.content.split('**').map((part, i) =>
                        i % 2 === 1
                            ? <strong key={i}>{part}</strong>
                            : <span key={i}>{part}</span>
                    )}
                </div>
            </div>
        );
    };

    return (
        <>
            {/* Floating Launcher Button */}
            <button
                onClick={() => setIsOpen(!isOpen)}
                className="fixed bottom-6 right-6 z-50 w-16 h-16 bg-primary rounded-full flex items-center justify-center shadow-2xl hover:brightness-110 transition-all hover:scale-110"
                style={{ boxShadow: '0 0 30px rgba(200, 255, 0, 0.3)' }}
            >
                <span className="material-symbols-outlined text-black text-3xl">
                    {isOpen ? 'close' : 'smart_toy'}
                </span>
            </button>

            {/* Chat Window */}
            {isOpen && (
                <div className="fixed bottom-24 right-6 z-50 w-[380px] max-w-[calc(100vw-2rem)] rounded-3xl overflow-hidden shadow-2xl border border-white/10"
                    style={{
                        background: 'linear-gradient(135deg, rgba(15,15,25,0.98), rgba(10,10,20,0.98))',
                        backdropFilter: 'blur(20px)',
                        maxHeight: 'min(600px, calc(100vh - 8rem))'
                    }}
                >
                    {/* Header */}
                    <div className="px-5 py-4 border-b border-white/10 flex items-center gap-3">
                        <div className="w-10 h-10 rounded-full bg-primary flex items-center justify-center">
                            <span className="material-symbols-outlined text-black">smart_toy</span>
                        </div>
                        <div className="flex-1">
                            <h3 className="font-bold text-white text-sm">Benry AI</h3>
                            <p className="text-xs text-green-400 flex items-center gap-1">
                                <span className="w-2 h-2 bg-green-400 rounded-full inline-block"></span>
                                En línea
                            </p>
                        </div>
                        <button
                            onClick={() => setIsOpen(false)}
                            className="w-8 h-8 rounded-full hover:bg-white/10 flex items-center justify-center transition-colors"
                        >
                            <span className="material-symbols-outlined text-slate-400 text-xl">close</span>
                        </button>
                    </div>

                    {/* Messages Area */}
                    <div className="h-[380px] overflow-y-auto p-4 space-y-1" style={{ scrollbarWidth: 'thin' }}>
                        {messages.map((msg, idx) => renderMessage(msg, idx))}

                        {/* Quick Actions (shown when only welcome message) */}
                        {messages.length <= 1 && (
                            <div className="space-y-2 mt-4">
                                <p className="text-xs text-slate-500 uppercase tracking-wider font-mono mb-2">Acciones rápidas</p>
                                {[
                                    { key: 'free', icon: 'rocket_launch', label: 'Comenzar Gratis', color: '#c8ff00' },
                                    { key: 'plans', icon: 'payments', label: 'Ver Planes y Precios', color: '#8b5cf6' },
                                    { key: 'demo', icon: 'event', label: 'Agendar Demo', color: '#3b82f6' },
                                    { key: 'support', icon: 'support_agent', label: 'Soporte Técnico', color: '#f59e0b' }
                                ].map(({ key, icon, label, color }) => (
                                    <button
                                        key={key}
                                        onClick={() => handleQuickAction(key)}
                                        className="w-full flex items-center gap-3 px-4 py-3 rounded-xl bg-white/5 hover:bg-white/10 transition-all text-left group"
                                    >
                                        <span className="material-symbols-outlined text-xl" style={{ color }}>{icon}</span>
                                        <span className="text-sm text-white/80 group-hover:text-white">{label}</span>
                                    </button>
                                ))}
                            </div>
                        )}

                        {/* Typing indicator */}
                        {isTyping && (
                            <div className="flex items-center gap-2 mb-3">
                                <div className="w-7 h-7 rounded-full bg-primary flex items-center justify-center flex-shrink-0">
                                    <span className="text-black text-xs font-bold">B</span>
                                </div>
                                <div className="bg-white/10 rounded-2xl px-4 py-3 rounded-bl-md">
                                    <div className="flex gap-1">
                                        <div className="w-2 h-2 bg-slate-400 rounded-full animate-bounce" style={{ animationDelay: '0ms' }}></div>
                                        <div className="w-2 h-2 bg-slate-400 rounded-full animate-bounce" style={{ animationDelay: '150ms' }}></div>
                                        <div className="w-2 h-2 bg-slate-400 rounded-full animate-bounce" style={{ animationDelay: '300ms' }}></div>
                                    </div>
                                </div>
                            </div>
                        )}

                        <div ref={messagesEndRef} />
                    </div>

                    {/* Input Area */}
                    <form onSubmit={handleSubmit} className="px-4 py-3 border-t border-white/10 flex gap-2">
                        <input
                            type="text"
                            value={input}
                            onChange={(e) => setInput(e.target.value)}
                            placeholder="Escribe tu mensaje..."
                            disabled={isTyping}
                            className="flex-1 bg-white/8 border border-white/10 rounded-xl px-4 py-2.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-primary/50 disabled:opacity-50 transition-colors"
                        />
                        <button
                            type="submit"
                            disabled={!input.trim() || isTyping}
                            className="w-10 h-10 rounded-xl bg-primary flex items-center justify-center text-black disabled:opacity-30 hover:brightness-110 transition-all"
                        >
                            <span className="material-symbols-outlined text-xl">send</span>
                        </button>
                    </form>
                </div>
            )}
        </>
    );
};

export default BenryChat;
