import OfficialLogo from './OfficialLogo';

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
                </div>
                <div>
                    <h4 className="font-mono text-xs tracking-widest uppercase text-slate-400 mb-6">Navegación</h4>
                    <ul className="space-y-3 font-light text-slate-500">
                        <li><a className="hover:text-primary transition-colors" href="#">Dashboard Portal</a></li>
                        <li><a className="hover:text-primary transition-colors" href="#">Centro de Ayuda</a></li>
                        <li><a className="hover:text-primary transition-colors" href="#">Documentación API</a></li>
                    </ul>
                </div>
                <div>
                    <h4 className="font-mono text-xs tracking-widest uppercase text-slate-400 mb-6">Legal</h4>
                    <ul className="space-y-3 font-light text-slate-500">
                        <li><a className="hover:text-primary transition-colors" href="#">Términos de Servicio</a></li>
                        <li><a className="hover:text-primary transition-colors" href="#">Privacidad</a></li>
                        <li><a className="hover:text-primary transition-colors" href="#">Cookies</a></li>
                    </ul>
                </div>
            </div>
            <div className="max-w-7xl mx-auto px-6 border-t border-white/5 pt-10 flex flex-col md:flex-row justify-between items-center gap-4">
                <p className="font-mono text-[10px] text-slate-600 uppercase tracking-widest text-center">© 2024 VENRIDESCREENS // TODOS LOS DERECHOS RESERVADOS</p>
                <div className="flex gap-6">
                    <a className="text-slate-600 hover:text-primary transition-all" href="#"><span className="material-symbols-outlined text-lg">public</span></a>
                    <a className="text-slate-600 hover:text-primary transition-all" href="#"><span className="material-symbols-outlined text-lg">share</span></a>
                    <a className="text-slate-600 hover:text-primary transition-all" href="#"><span className="material-symbols-outlined text-lg">terminal</span></a>
                </div>
            </div>
        </footer>
    );
};

export default Footer;
