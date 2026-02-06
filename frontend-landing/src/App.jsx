import React, { useState } from 'react';
import Navbar from './components/Navbar';
import Hero from './components/Hero';
import Comparison from './components/Comparison';
import Pricing from './components/Pricing';
import Footer from './components/Footer';
import BenryChat from './components/BenryChat';
import ContactModal from './components/ContactModal';

function App() {
    const [isContactOpen, setIsContactOpen] = useState(false);

    return (
        <div className="relative min-h-screen">
            <Navbar />
            <Hero onOpenContact={() => setIsContactOpen(true)} />
            <Comparison />
            <Pricing onOpenContact={() => setIsContactOpen(true)} />
            <Footer />
            <BenryChat onOpenContact={() => setIsContactOpen(true)} />

            <ContactModal
                isOpen={isContactOpen}
                onClose={() => setIsContactOpen(false)}
            />
        </div>
    );
}

export default App;
