import React from 'react';
import fondo2 from '../assets/fondo2.png';
import fija1 from '../assets/fija1.png';

const Hero = () => {
    return (
        <section className="relative min-h-screen pt-32 pb-20 flex flex-col items-center justify-center overflow-hidden hero-gradient">
            <div className="absolute inset-0 z-0 opacity-40">
                <img
                    alt="High-end digital display in a modern environment"
                    className="w-full h-full object-cover mix-blend-overlay"
                    src="https://lh3.googleusercontent.com/aida-public/AB6AXuAcYjLaUC5WxhtApgOfZPknqyJPlWRpLIP1WK6ZPmNSjs5zV6xab5KGY1bu6AXxn6NoOFF1uFoSb4tAF7M6K4VpVRW-0JvGGl1EB4rs_ewXyPcpVhSS5MSynriTZvPN9pG92POrSFxcYMNtBxdtRpjZlgKCQ6pGUSg3mQ-y_l5MI-6lA-QLDhUvGAsbvZKdDjQLPGnxKY-s_HmOitAoSkc2g22GMqYvLyDMmE-jf7yHojU4mD2Ok9nHh9gUQmXZyuLFAWJnG3iHmQ"
                />
            </div>
            <div className="relative z-10 max-w-5xl mx-auto px-6 text-center">
                <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-full h-[600px] z-0 opacity-50 pointer-events-none">
                    <div className="absolute inset-0 bg-radial-gradient from-transparent to-background-light dark:to-background-dark pointer-events-none z-10"></div>
                    <img
                        src={fondo2}
                        alt="Background Decorative"
                        className="w-full h-full object-contain"
                    />
                </div>
                <h1 className="text-6xl md:text-9xl font-black uppercase italic tracking-tighter mb-2 leading-none relative z-10">
                    PANTALLAS QUE <span className="text-primary italic">VENDEN</span>
                </h1>
                <p className="text-primary font-mono text-sm tracking-[0.3em] uppercase mb-12">
                    Pantallas Publi-Inteligentes
                </p>
                <p className="text-xl md:text-2xl text-slate-400 max-w-2xl mx-auto mb-12 font-light">
                    Señalizador Digital simple y sincronizado. Gestiona contenidos Publicitario de forma inteligente en todas tus pantallas, en cualquier lugar.
                </p>
                <div className="flex flex-col sm:flex-row gap-4 justify-center">
                    <button className="bg-primary text-black text-lg px-10 py-4 rounded-xl font-extrabold hover:shadow-[0_0_30px_rgba(0,204,255,0.5)] transition-all flex items-center justify-center gap-2">
                        COMENZAR GRATIS <span className="material-symbols-outlined">arrow_forward</span>
                    </button>
                    <button className="glass text-white text-lg px-10 py-4 rounded-xl font-bold hover:bg-white/10 transition-all border border-white/20">
                        VER DEMOSTRACIÓN
                    </button>
                </div>
            </div>
            <div className="relative z-10 mt-20 w-full max-w-6xl px-6">
                <div className="glass rounded-2xl p-2 border border-white/20 neon-glow">
                    <img
                        alt="Señalización Fija"
                        className="rounded-xl w-full h-auto"
                        src={fija1}
                    />
                </div>
            </div>
        </section>
    );
};

export default Hero;
