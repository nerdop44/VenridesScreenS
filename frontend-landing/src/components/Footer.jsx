import OfficialLogo from './OfficialLogo';
import { site, legalLinks } from '../config/site';
import { resetConsent } from './CookieConsent';

const Footer = () => {
    return (
        <footer className="bg-black border-t border-white/10 pt-20 pb-10">
            <div className="max-w-7xl mx-auto px-6 grid md:grid-cols-4 gap-12 mb-20">
                <div className="col-span-2">
                    <div className="mb-8">
                        <OfficialLogo className="h-12" />
                    </div>
                    <p className="text-slate-500 max-w-sm font-light leading-relaxed">
                        Transformamos espacios físicos en experiencias digitales dinámicas. Líderes en tecnología publicitaria inteligente para entornos corporativos y comerciales.
                    </p>
                    <p className="mt-6 text-slate-500 text-sm font-light">
                        {site.legalName} · RIF {site.rif}<br />
                        {site.address}, {site.country}<br />
                        <a className="text-primary hover:underline" href={`mailto:${site.contactEmail}`}>{site.contactEmail}</a>
                    </p>
                </div>
                <div>
                    <h4 className="font-mono text-xs tracking-widest uppercase text-slate-400 mb-6">Navegación</h4>
                    <ul className="space-y-3 font-light text-slate-500">
                        <li><a className="hover:text-primary transition-colors" href={site.appUrl} target="_blank" rel="noopener noreferrer">Portal de clientes</a></li>
                        <li><a className="hover:text-primary transition-colors" href="/app">App móvil (APK)</a></li>
                        <li><a className="hover:text-primary transition-colors" href="/tv-app">App TV (APK)</a></li>
                        <li><a className="hover:text-primary transition-colors" href={`mailto:${site.contactEmail}`}>Centro de ayuda</a></li>
                        <li><a className="hover:text-primary transition-colors" href={`${site.apiUrl}/docs`} target="_blank" rel="noopener noreferrer">Documentación API</a></li>
                    </ul>
                </div>
                <div>
                    <h4 className="font-mono text-xs tracking-widest uppercase text-slate-400 mb-6">Legal</h4>
                    <ul className="space-y-3 font-light text-slate-500">
                        {legalLinks.map((link) => (
                            <li key={link.href}>
                                <a className="hover:text-primary transition-colors" href={link.href}>{link.label}</a>
                            </li>
                        ))}
                        <li>
                            <button
                                type="button"
                                onClick={resetConsent}
                                className="hover:text-primary transition-colors text-left"
                            >
                                Preferencias de cookies
                            </button>
                        </li>
                    </ul>
                </div>
            </div>
            <div className="max-w-7xl mx-auto px-6 border-t border-white/5 pt-10 flex flex-col md:flex-row justify-between items-center gap-4">
                <p className="font-mono text-[10px] text-slate-600 uppercase tracking-widest text-center">
                    © {new Date().getFullYear()} {site.brand} // TODOS LOS DERECHOS RESERVADOS
                </p>
                <div className="flex gap-6">
                    <a className="text-slate-600 hover:text-primary transition-all" href={site.landingUrl} aria-label="Sitio web">
                        <span className="material-symbols-outlined text-lg">public</span>
                    </a>
                    <a className="text-slate-600 hover:text-primary transition-all" href={`mailto:${site.contactEmail}`} aria-label="Correo de contacto">
                        <span className="material-symbols-outlined text-lg">mail</span>
                    </a>
                    <a className="text-slate-600 hover:text-primary transition-all" href={site.appUrl} aria-label="Portal de clientes">
                        <span className="material-symbols-outlined text-lg">terminal</span>
                    </a>
                </div>
            </div>
        </footer>
    );
};

export default Footer;
