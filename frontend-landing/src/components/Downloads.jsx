import React from 'react';
import { site } from '../config/site';

const APPS = [
    {
        id: 'mobile',
        icon: 'smartphone',
        name: 'VScreenS Móvil',
        description: 'Gestiona pantallas, contenido, alertas y métricas desde tu teléfono.',
        href: '/app',
        meta: 'Android 8+ · APK firmado · v2.0',
    },
    {
        id: 'tv',
        icon: 'tv',
        name: 'VScreenS TV',
        description: 'Instala el reproductor en Android TV, Fire TV o un televisor Android.',
        href: '/tv-app',
        meta: 'Android TV · APK firmado · v2.0',
    },
];

const Downloads = () => {
    return (
        <section id="descargas" className="relative py-24 border-t border-white/10 bg-black">
            <div className="max-w-6xl mx-auto px-6">
                <div className="text-center mb-14">
                    <p className="text-primary font-mono text-xs tracking-[0.3em] uppercase mb-4">
                        Aplicaciones oficiales
                    </p>
                    <h2 className="text-4xl md:text-5xl font-black uppercase italic tracking-tighter">
                        Descarga <span className="text-primary">VScreenS</span>
                    </h2>
                    <p className="text-slate-400 font-light max-w-2xl mx-auto mt-5">
                        Instala la app en tu teléfono para administrar tu red de pantallas y en tu
                        televisor para reproducir el contenido. Sin intermediarios.
                    </p>
                </div>

                <div className="grid md:grid-cols-2 gap-6">
                    {APPS.map((app) => (
                        <article
                            key={app.id}
                            className="glass rounded-2xl p-8 border border-white/15 flex flex-col gap-5"
                        >
                            <div className="flex items-center gap-4">
                                <span className="material-symbols-outlined text-4xl text-primary" aria-hidden="true">
                                    {app.icon}
                                </span>
                                <h3 className="text-2xl font-bold">{app.name}</h3>
                            </div>
                            <p className="text-slate-400 font-light leading-relaxed flex-1">
                                {app.description}
                            </p>
                            <p className="font-mono text-[11px] uppercase tracking-widest text-slate-500">
                                {app.meta}
                            </p>
                            <a
                                href={app.href}
                                className="bg-[#00CCFF] text-black font-black text-center px-6 py-3 rounded-xl hover:shadow-[0_0_30px_rgba(0,204,255,0.7)] transition-all inline-flex items-center justify-center gap-2"
                                download
                            >
                                <span className="material-symbols-outlined">download</span>
                                Descargar APK
                            </a>
                        </article>
                    ))}
                </div>

                <p className="text-center text-xs text-slate-600 font-light mt-8">
                    ¿Usas iPhone, iPad o Smart TV de otra marca? El panel funciona en cualquier
                    navegador moderno desde{' '}
                    <a className="text-primary hover:underline" href={site.appUrl}>
                        {site.appUrl.replace('https://', '')}
                    </a>
                    .
                </p>
            </div>
        </section>
    );
};

export default Downloads;
