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
import SEO from './components/SEO';
import { site } from './config/site';

const LEGAL_SLUGS = [
  'aviso-legal',
  'terminos',
  'privacidad',
  'cookies',
  'devoluciones',
  'seguridad',
];

function getSlug() {
  const path = window.location.pathname.replace(/\/+$/, '');
  const slug = path.split('/').filter(Boolean).pop() || '';
  return LEGAL_SLUGS.includes(slug) ? slug : null;
}

const LEGAL_TITLES = {
  'aviso-legal': 'Aviso legal',
  terminos: 'Términos y condiciones',
  privacidad: 'Política de privacidad',
  cookies: 'Política de cookies',
  devoluciones: 'Devoluciones y cancelaciones',
  seguridad: 'Seguridad',
};

const LEGAL_DESCRIPTIONS = {
  'aviso-legal':
    'Documento legal de VScreenS: aviso legal. Información sobre el titular, objeto, propiedad intelectual y legislación aplicable.',
  terminos:
    'Términos y condiciones de uso de la plataforma VScreenS. Planes, precios, pagos, uso aceptable y limitación de responsabilidad.',
  privacidad:
    'Política de privacidad de VScreenS. Datos que tratamos, finalidades, conservación, derechos del titular y seguridad.',
  cookies:
    'Política de cookies de VScreenS. Tipos de cookies, consentimiento y gestión de preferencias.',
  devoluciones:
    'Política de devoluciones y cancelaciones de VScreenS. Cancelación de suscripciones y solicitud de reembolsos.',
  seguridad:
    'Seguridad de la información de VScreenS. Medidas técnicas, responsabilidades del cliente y reporte de vulnerabilidades.',
};

function App() {
  const [isContactOpen, setIsContactOpen] = useState(false);
  const [legalSlug, setLegalSlug] = useState(() => getSlug());

  useEffect(() => {
    const onPopState = () => setLegalSlug(getSlug());
    window.addEventListener('popstate', onPopState);
    return () => window.removeEventListener('popstate', onPopState);
  }, []);

  const isLegal = Boolean(legalSlug);
  const pageTitle = isLegal ? LEGAL_TITLES[legalSlug] : null;
  const pageDescription = isLegal ? LEGAL_DESCRIPTIONS[legalSlug] : null;
  const pageUrl = isLegal ? `/${legalSlug}` : '/';

  const breadcrumbs = isLegal
    ? [
        { label: 'Inicio', href: '/' },
        { label: 'Legal', href: '#' },
        { label: LEGAL_TITLES[legalSlug], href: pageUrl },
      ]
    : null;

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
        <SEO
          title={pageTitle}
          description={pageDescription}
          url={pageUrl}
          breadcrumbs={breadcrumbs}
        />
        <Navbar />
        <LegalPage slug={legalSlug} />
        <Footer />
        <CookieConsent />
      </div>
    );
  }

  return (
    <div className="relative min-h-screen">
      <SEO title={null} description={null} url="/" />
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
