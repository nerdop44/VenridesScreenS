import React, { useEffect, useState } from 'react';
import Navbar from './components/Navbar';
import Hero from './components/Hero';
import Comparison from './components/Comparison';
import Pricing from './components/Pricing';
import Downloads from './components/Downloads';
import Footer from './components/Footer';
import BenryChat from './components/BenryChat';
import ContactModal from './components/ContactModal';
import LegalPage from './components/LegalPage';
import CookieConsent, { hasAnalyticsConsent } from './components/CookieConsent';
import { site } from './config/site';

const LEGAL_SLUGS = ['aviso-legal', 'terminos', 'privacidad', 'cookies', 'devoluciones', 'seguridad'];

function getSlug() {
  const path = window.location.pathname.replace(/\/+$/, '');
  const slug = path.split('/').filter(Boolean).pop() || '';
  return LEGAL_SLUGS.includes(slug) ? slug : null;
}

function setMeta(name, content) {
  let el = document.querySelector(`meta[name="${name}"]`);
  if (!el) {
    el = document.createElement('meta');
    el.setAttribute('name', name);
    document.head.appendChild(el);
  }
  el.setAttribute('content', content);
}

function App() {
  const [isContactOpen, setIsContactOpen] = useState(false);
  const [legalSlug, setLegalSlug] = useState(() => getSlug());

  useEffect(() => {
    const onPopState = () => setLegalSlug(getSlug());
    window.addEventListener('popstate', onPopState);
    return () => window.removeEventListener('popstate', onPopState);
  }, []);

  useEffect(() => {
    const isLegal = Boolean(legalSlug);
    document.title = isLegal
      ? `${legalSlug.replace('-', ' ').replace(/\b\w/g, c => c.toUpperCase())} | ${site.brand}`
      : `${site.brand} | Pantallas inteligentes para tu negocio`;

    setMeta('description', isLegal
      ? `Documento legal de ${site.brand}: ${legalSlug.replace('-', ' ')}.`
      : 'Plataforma de señalización digital para gestionar pantallas, contenido, publicidad y alertas desde un solo panel.');

    let canonical = document.querySelector('link[rel="canonical"]');
    if (!canonical) {
      canonical = document.createElement('link');
      canonical.setAttribute('rel', 'canonical');
      document.head.appendChild(canonical);
    }
    canonical.setAttribute('href', `${site.landingUrl}${isLegal ? `/${legalSlug}` : '/'}`);
  }, [legalSlug]);

  useEffect(() => {
    if (legalSlug) return;
    if (!hasAnalyticsConsent()) return;
    const trackVisit = async () => {
      try {
        const API_BASE = import.meta.env.VITE_API_BASE_URL || site.apiUrl;
        await fetch(`${API_BASE}/analytics/track`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            page: window.location.pathname,
            referrer: document.referrer,
          }),
        });
      } catch (e) {
        console.warn('Analytics track failed');
      }
    };
    trackVisit();
  }, [legalSlug]);

  if (legalSlug) {
    return (
      <div className="relative min-h-screen">
        <Navbar />
        <LegalPage slug={legalSlug} />
        <Footer />
        <CookieConsent />
      </div>
    );
  }

  return (
    <div className="relative min-h-screen">
      <Navbar />
      <Hero onOpenContact={() => setIsContactOpen(true)} />
      <Comparison />
      <Pricing onOpenContact={() => setIsContactOpen(true)} />
      <Downloads />
      <Footer />
      <BenryChat onOpenContact={() => setIsContactOpen(true)} />
      <CookieConsent />

      <ContactModal
        isOpen={isContactOpen}
        onClose={() => setIsContactOpen(false)}
      />
    </div>
  );
}

export default App;
