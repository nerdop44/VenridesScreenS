import React, { useEffect, useState } from 'react';

const STORAGE_KEY = 'venrides_cookie_consent';

export function getConsent() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

export function hasAnalyticsConsent() {
  const consent = getConsent();
  return Boolean(consent?.analytics);
}

export function saveConsent(analytics) {
  const value = {
    necessary: true,
    analytics: Boolean(analytics),
    date: new Date().toISOString(),
    version: 1,
  };
  localStorage.setItem(STORAGE_KEY, JSON.stringify(value));
  window.dispatchEvent(new Event('venrides-consent-change'));
  return value;
}

export function resetConsent() {
  localStorage.removeItem(STORAGE_KEY);
  window.dispatchEvent(new Event('venrides-consent-change'));
}

export default function CookieConsent() {
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    const check = () => setVisible(!getConsent());
    check();
    window.addEventListener('venrides-consent-change', check);
    return () => window.removeEventListener('venrides-consent-change', check);
  }, []);

  if (!visible) return null;

  return (
    <div className="fixed bottom-4 left-4 right-4 z-[100] md:left-auto md:max-w-xl">
      <div className="glass border border-white/15 rounded-2xl p-5 shadow-2xl bg-black/90 backdrop-blur-xl">
        <div className="flex items-start gap-3">
          <span className="material-symbols-outlined text-primary mt-0.5">cookie</span>
          <div className="text-sm text-slate-300 font-light leading-relaxed">
            <p className="mb-2">
              Usamos cookies necesarias para el funcionamiento del sitio y, con tu consentimiento, cookies
              analíticas para mejorar el servicio. Puedes aceptar todas o solo las necesarias.
            </p>
            <a href="/cookies" className="text-primary underline underline-offset-4 text-xs font-mono uppercase tracking-wider">
              Ver política de cookies
            </a>
          </div>
        </div>
        <div className="mt-4 flex flex-wrap gap-2 justify-end">
          <button
            type="button"
            onClick={() => { saveConsent(false); setVisible(false); }}
            className="px-4 py-2 rounded-lg border border-white/20 text-slate-300 text-sm hover:bg-white/5 transition-colors"
          >
            Solo necesarias
          </button>
          <button
            type="button"
            onClick={() => { saveConsent(true); setVisible(false); }}
            className="px-4 py-2 rounded-lg bg-primary text-black text-sm font-bold hover:brightness-110 transition-all"
          >
            Aceptar todas
          </button>
        </div>
      </div>
    </div>
  );
}
