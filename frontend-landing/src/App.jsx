import React from 'react';
import Navbar from './components/Navbar';
import Hero from './components/Hero';
import FijaSection from './components/FijaSection';
import Comparison from './components/Comparison';
import Pricing from './components/Pricing';
import Footer from './components/Footer';
import BenryChat from './components/BenryChat';

function App() {
    return (
        <div className="relative min-h-screen">
            <Navbar />
            <Hero />
            <FijaSection />
            <Comparison />
            <Pricing />
            <Footer />
            <BenryChat />
        </div>
    );
}

export default App;
