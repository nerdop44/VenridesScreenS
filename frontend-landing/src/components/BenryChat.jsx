import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';

const BenryChat = ({ onOpenContact }) => {
    const [isOpen, setIsOpen] = useState(false);

    const toggleChat = () => setIsOpen(!isOpen);

    const quickActions = [
        { label: '🚀 Comenzar Gratis', action: () => { window.location.href = '#precios'; setIsOpen(false); } },
        { label: '📅 Agendar Demo', action: () => { onOpenContact(); setIsOpen(false); } },
        { label: '💬 Soporte Técnico', action: () => { onOpenContact(); setIsOpen(false); } }
    ];

    return (
        <div className="fixed bottom-8 right-8 z-[100]">
            {/* Chat Window */}
            <AnimatePresence>
                {isOpen && (
                    <motion.div
                        initial={{ opacity: 0, scale: 0.8, y: 20, x: 20 }}
                        animate={{ opacity: 1, scale: 1, y: 0, x: 0 }}
                        exit={{ opacity: 0, scale: 0.8, y: 20, x: 20 }}
                        className="absolute bottom-20 right-0 w-[350px] glass border border-primary/30 rounded-3xl shadow-2xl overflow-hidden flex flex-col"
                    >
                        {/* Header */}
                        <div className="bg-primary p-4 flex items-center justify-between">
                            <div className="flex items-center gap-3">
                                <div className="w-10 h-10 bg-black rounded-full flex items-center justify-center">
                                    <span className="material-symbols-outlined text-primary">smart_toy</span>
                                </div>
                                <div>
                                    <h4 className="text-black font-black text-sm uppercase leading-none">Benry AI</h4>
                                    <span className="text-black/60 text-[10px] uppercase font-bold tracking-widest">En Línea</span>
                                </div>
                            </div>
                            <button onClick={toggleChat} className="text-black/60 hover:text-black transition-colors">
                                <span className="material-symbols-outlined">close</span>
                            </button>
                        </div>

                        {/* Messages Area */}
                        <div className="p-6 space-y-4 max-h-[400px] overflow-y-auto bg-black/40">
                            <div className="flex flex-col gap-2">
                                <div className="bg-primary/10 border border-primary/20 p-4 rounded-2xl rounded-tl-none max-w-[90%]">
                                    <p className="text-sm text-white font-light leading-relaxed">
                                        ¡Hola! Soy <span className="text-primary font-bold">Benry</span>, tu copiloto de VenridesScreenS.
                                        ¿Cómo puedo transformar tus pantallas hoy?
                                    </p>
                                </div>
                                <span className="text-[10px] text-white/30 font-mono ml-1 uppercase">Benry • Justo ahora</span>
                            </div>

                            {/* Quick Actions List */}
                            <div className="space-y-2 pt-4 border-t border-white/5">
                                <p className="text-[10px] text-primary font-bold uppercase tracking-widest mb-3">Acciones rápidas</p>
                                {quickActions.map((item, i) => (
                                    <button
                                        key={i}
                                        onClick={item.action}
                                        className="w-full text-left p-3 rounded-xl bg-white/5 border border-white/10 hover:border-primary/50 hover:bg-primary/5 transition-all text-sm font-medium flex items-center justify-between group"
                                    >
                                        {item.label}
                                        <span className="material-symbols-outlined text-xs opacity-0 group-hover:opacity-100 transition-opacity">chevron_right</span>
                                    </button>
                                ))}
                            </div>
                        </div>

                        {/* Footer Input Placeholder */}
                        <div className="p-4 border-t border-white/10 bg-black/60">
                            <div className="relative">
                                <input
                                    type="text"
                                    placeholder="Escribe tu duda técnica..."
                                    className="w-full bg-white/5 border border-white/10 rounded-full px-4 py-2 text-xs focus:outline-none focus:border-primary transition-colors pr-10"
                                />
                                <span className="material-symbols-outlined absolute right-3 top-1/2 -translate-y-1/2 text-primary text-sm">send</span>
                            </div>
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>

            {/* Launcher Button */}
            <div className="flex items-center gap-3">
                <AnimatePresence>
                    {!isOpen && (
                        <motion.div
                            initial={{ opacity: 0, x: 20 }}
                            animate={{ opacity: 1, x: 0 }}
                            exit={{ opacity: 0, x: 20 }}
                            className="bg-black/80 backdrop-blur-md px-4 py-2 rounded-full border border-primary/30 pointer-events-none shadow-xl"
                        >
                            <p className="text-xs font-bold text-white whitespace-nowrap">¡Hola! Soy <span className="text-primary">Benry</span>, ¿en qué puedo ayudarte?</p>
                        </motion.div>
                    )}
                </AnimatePresence>
                <button
                    onClick={toggleChat}
                    className={`w-16 h-16 rounded-full flex items-center justify-center transition-all duration-500 shadow-2xl ${isOpen ? 'bg-black border border-primary/50 rotate-90 scale-90' : 'bg-primary neon-glow pulse-neon hover:scale-110'
                        }`}
                >
                    <span className={`material-symbols-outlined text-3xl font-bold transition-colors ${isOpen ? 'text-primary' : 'text-black'}`}>
                        {isOpen ? 'close' : 'smart_toy'}
                    </span>
                </button>
            </div>
        </div>
    );
};

export default BenryChat;
