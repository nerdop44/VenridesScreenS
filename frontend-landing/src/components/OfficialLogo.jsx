import React from 'react';
import logoPng from '../../logo-imagenes/logo.png';

const OfficialLogo = ({ className = "h-16", showSlogan = true, variant = "full" }) => {
    // Definimos el estilo del contorno blanco y la sombra sutil para igualar el Admin Panel
    const logoStyle = {
        filter: 'drop-shadow(1px 1px 0 #fff) drop-shadow(-1px -1px 0 #fff) drop-shadow(1px -1px 0 #fff) drop-shadow(-1px 1px 0 #fff) drop-shadow(0 4px 15px rgba(0,0,0,0.3))',
        transition: 'transform 0.3s ease',
        width: 'auto',
        height: '100%',
        objectFit: 'contain'
    };

    return (
        <div className={`flex items-center gap-4 ${className} hover:scale-105 transition-transform cursor-pointer`} style={{ minHeight: className.includes('h-') ? undefined : '64px' }}>
            <img
                src={logoPng}
                alt="Venrides Screens Official Logo"
                style={logoStyle}
            />
        </div>
    );
};

export default OfficialLogo;
