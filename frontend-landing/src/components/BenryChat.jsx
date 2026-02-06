import React from 'react';

const BenryChat = () => {
    return (
        <div className="fixed bottom-8 right-8 z-[100] group">
            <div className="flex items-center gap-3">
                <div className="bg-black/80 backdrop-blur-md px-4 py-2 rounded-full border border-primary/30 opacity-0 group-hover:opacity-100 transition-opacity transform translate-x-2 group-hover:translate-x-0">
                    <p className="text-xs font-bold text-white whitespace-nowrap">¡Hola! Soy <span className="text-primary">Benry</span>, ¿en qué puedo ayudarte?</p>
                </div>
                <button className="w-16 h-16 bg-primary rounded-full flex items-center justify-center neon-glow shadow-[0_0_20px_rgba(0,204,255,0.4)] hover:scale-110 transition-transform pulse-neon">
                    <span className="material-symbols-outlined text-black text-3xl font-bold">smart_toy</span>
                </button>
            </div>
        </div>
    );
};

export default BenryChat;
