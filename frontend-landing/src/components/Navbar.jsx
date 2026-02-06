import OfficialLogo from './OfficialLogo';

const Navbar = () => {
    return (
        <nav className="fixed w-full z-50 top-0 glass border-b border-white/10">
            <div className="max-w-7xl mx-auto px-6 h-20 flex items-center justify-between">
                <div className="flex items-center">
                    <OfficialLogo className="h-20" showSlogan={false} />
                </div>
                <div className="hidden md:flex items-center gap-8 font-mono text-sm uppercase tracking-widest">
                    <a className="hover:text-primary transition-colors" href="#soluciones">Soluciones</a>
                    <a className="hover:text-primary transition-colors" href="#precios">Precios</a>
                    <a className="hover:text-primary transition-colors" href="#">Casos de Éxito</a>
                    <a href={`${import.meta.env.VITE_ADMIN_PANEL_URL}?logout=true`} target="_blank" rel="noopener noreferrer" className="bg-primary text-black px-6 py-2 rounded-full font-bold hover:scale-105 transition-transform">PORTAL CLIENTES</a>
                </div>
            </div>
        </nav>
    );
};

export default Navbar;
