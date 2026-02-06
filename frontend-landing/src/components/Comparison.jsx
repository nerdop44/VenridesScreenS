import React from 'react';
import Carousel from './Carousel';

const Comparison = () => {
    return (
        <section className="py-32 bg-background-light dark:bg-background-dark relative overflow-hidden" id="soluciones">
            <div className="max-w-7xl mx-auto px-6">
                <div className="grid lg:grid-cols-2 gap-20 items-center">
                    <div>
                        <h2 className="text-4xl md:text-6xl font-black uppercase mb-8 leading-tight">
                            Señalización Digital <span className="text-primary">Sincronizada</span> y Simple.
                        </h2>
                        <p className="text-lg text-slate-400 mb-10 font-light leading-relaxed">
                            Nuestra plataforma inteligente permite el control total de tus pantallas desde un único panel. Automatiza, programa y analiza el impacto de cada mensaje, vende y entretiene al mismo tiempo, <span className="text-primary font-bold italic">"Tu Publicidad en Tus Pantallas"</span>.
                        </p>
                        <div className="grid gap-6">
                            <div className="flex gap-4 p-6 glass rounded-2xl hover:border-primary/50 transition-colors">
                                <div className="w-12 h-12 bg-primary/10 rounded-lg flex items-center justify-center flex-shrink-0">
                                    <span className="material-symbols-outlined text-primary">sync</span>
                                </div>
                                <div>
                                    <h3 className="text-xl font-bold mb-2">Sincronización Total</h3>
                                    <p className="text-slate-400 text-sm">Cambia el contenido de tus pantallas en tiempo real con un solo clic.</p>
                                </div>
                            </div>
                            <div className="flex gap-4 p-6 glass rounded-2xl hover:border-primary/50 transition-colors">
                                <div className="w-12 h-12 bg-primary/10 rounded-lg flex items-center justify-center flex-shrink-0">
                                    <span className="material-symbols-outlined text-primary">monitoring</span>
                                </div>
                                <div>
                                    <h3 className="text-xl font-bold mb-2">Contenido Dinámico</h3>
                                    <p className="text-slate-400 text-sm">Programa horarios, gestiona múltiples ubicaciones y actualiza contenido publicitario en tiempo real.</p>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div className="relative">
                        <div className="aspect-square glass rounded-3xl overflow-hidden neon-border">
                            <Carousel />
                            <div className="absolute inset-0 bg-gradient-to-t from-black/60 via-transparent to-transparent pointer-events-none"></div>
                            <div className="absolute bottom-8 left-8">
                                <span className="bg-primary text-black font-mono text-xs px-3 py-1 rounded-full font-bold mb-2 inline-block uppercase tracking-widest">Live Status</span>
                                <p className="text-2xl font-bold">Instalaciones Reales</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </section>
    );
};

export default Comparison;
