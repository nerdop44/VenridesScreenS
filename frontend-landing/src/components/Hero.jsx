import React from 'react';

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
                <h1 className="text-6xl md:text-9xl font-black uppercase italic tracking-tighter mb-2 leading-none">
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
                        alt="Application interface dashboard"
                        className="rounded-xl w-full h-auto"
                        src="https://lh3.googleusercontent.com/aida-public/AB6AXuDDqftoI0KnRY__l6yburXbx4u2iTU9bYiq2vobgWQfe2XHlKrcmja2z_Ef1aUNh4Zk-NZ3L6HhiawkUQYhUGskseq--PAHOF4Yq24G6fYg9hgsT29C1R9CO2el365Wxzl7SiD5OlUFce9MXcnJUKHKP5nc2ivcf1pxQumKbZLgdZSd66apTZ-kE3QincGPFjWYhYHWs7iTdX14ZgqKC1nVP8xSd5Y7FqHxjgMGYA9riH77LXw-Jso4vbimz6b_LvxAL61mhLgBmg"
                    />
                </div>
            </div>
        </section>
    );
};

export default Hero;
