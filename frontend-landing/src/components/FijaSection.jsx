import React from 'react';
import fija1 from '../assets/fija1.png';

const FijaSection = () => {
    return (
        <section className="w-full bg-background-light dark:bg-background-dark py-10">
            <div className="max-w-7xl mx-auto">
                <img
                    src={fija1}
                    alt="Propaganda Fija"
                    className="w-full h-auto object-contain rounded-3xl neon-glow"
                />
            </div>
        </section>
    );
};

export default FijaSection;
