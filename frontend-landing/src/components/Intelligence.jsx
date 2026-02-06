import React from 'react';
import { motion } from 'framer-motion';
import { Target, Users, Eye } from 'lucide-react';

const Intelligence = () => {
    return (
        <section id="inteligencia" className="section-padding relative">
            <div className="container-elite grid lg:grid-cols-2 gap-24 items-center">
                {/* Technical Visualization */}
                <div className="relative">
                    <div className="aspect-square glass-card p-2 relative overflow-hidden group">
                        <div className="absolute inset-0 bg-black/40 z-10"></div>
                        <img
                            src="https://images.unsplash.com/photo-1557683316-973673baf926?q=80&w=2029&auto=format&fit=crop"
                            className="w-full h-full object-cover grayscale opacity-50 transition-all duration-700 group-hover:grayscale-0 group-hover:opacity-100"
                        />
                        {/* Target Overlay */}
                        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-20 w-32 h-32 border-2 border-electric-blue animate-pulse">
                            <div className="absolute top-0 left-0 w-4 h-4 border-t-4 border-l-4 border-electric-blue -translate-x-2 -translate-y-2"></div>
                            <div className="absolute bottom-0 right-0 w-4 h-4 border-b-4 border-r-4 border-electric-blue translate-x-2 translate-y-2"></div>
                        </div>
                        {/* Meta Data Tags */}
                        <div className="absolute top-10 left-10 z-20 space-y-2">
                            <div className="bg-electric-blue text-black text-[9px] font-black px-2 py-1 uppercase tracking-widest">Male / 25-30</div>
                            <div className="bg-white text-black text-[9px] font-black px-2 py-1 uppercase tracking-widest">Engagement: High</div>
                        </div>
                    </div>
                    {/* Decorative scanner line */}
                    <div className="absolute top-0 left-0 right-0 h-[2px] bg-electric-blue shadow-[0_0_15px_rgba(0,204,255,1)] z-30 animate-scan"></div>
                </div>

                {/* Content */}
                <div>
                    <span className="text-electric-blue text-[10px] font-bold tracking-[0.3em] uppercase mb-4 block">Visual Vision</span>
                    <h2 className="text-5xl md:text-7xl mb-12">Inteligencia <br /> <span className="text-white/20">Contextual</span></h2>

                    <div className="space-y-12">
                        {[
                            { icon: <Target className="text-electric-blue" />, title: "Detección Precisa", desc: "Segmentamos por edad, género y nivel de atención sin almacenar datos personales." },
                            { icon: <Users className="text-electric-blue" />, title: "Adaptación en Vivo", desc: "La pantalla cambia su oferta al instante basándose en quién está en frente." },
                            { icon: <Eye className="text-electric-blue" />, title: "Análisis de Mirada", desc: "Mide cuánto tiempo real pasan mirando tu anuncio para optimizar el ROI." }
                        ].map((item, i) => (
                            <div key={i} className="flex gap-6 items-start group">
                                <div className="mt-1 transition-transform duration-300 group-hover:rotate-12">{item.icon}</div>
                                <div>
                                    <h4 className="text-lg mb-2 group-hover:text-electric-blue transition-colors">{item.title}</h4>
                                    <p className="text-white/50 font-light text-sm leading-relaxed">{item.desc}</p>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            </div>
        </section>
    );
};

export default Intelligence;
