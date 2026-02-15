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

    React.useEffect(() => {
        // Track page visit
        const trackVisit = async () => {
            try {
                const API_BASE = import.meta.env.VITE_API_BASE_URL || "/api";
                await fetch(`${API_BASE}/analytics/track`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        page: window.location.pathname,
                        referrer: document.referrer
                    })
                });
            } catch (e) {
                console.warn("Analytics track failed");
            }
        };
        trackVisit();
    }, []);

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
