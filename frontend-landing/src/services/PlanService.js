const API_BASE = import.meta.env.VITE_API_BASE_URL || 'https://vscreens-api.inverpave.com';

/**
 * Planes por defecto (fallback). La fuente de verdad es el backend/Odoo.
 * El backend puede devolver la misma estructura en GET /api/plans.
 */
export const FALLBACK_PLANS = [
  {
    id: 'free',
    code: 'free',
    name: 'Free',
    subtitle: 'Starter',
    monthlyPrice: 0,
    annualPrice: 0,
    screens: '2 pantallas',
    features: [
      'Hasta 2 pantallas',
      'Contenido publicitario básico',
      'Programación de publicidad',
      'Panel web completo',
      'Publicidad de terceros',
      'Soporte Helpdesk',
    ],
  },
  {
    id: 'basic',
    code: 'basic',
    name: 'Emprendedor',
    subtitle: 'Básico',
    monthlyPrice: 30,
    annualPrice: 320,
    screens: '5 pantallas',
    features: [
      'Hasta 5 pantallas',
      'Contenido publicitario',
      'Sin publicidad de terceros',
      'Programación avanzada',
      'Panel web completo',
      'Multi-ubicación',
      'Soporte Helpdesk',
    ],
  },
  {
    id: 'plus',
    code: 'plus',
    name: 'Profesional',
    subtitle: 'Plus',
    monthlyPrice: 50,
    annualPrice: 520,
    screens: '10 pantallas',
    popular: true,
    features: [
      'Hasta 10 pantallas',
      'Contenido publicitario',
      'Sin publicidad de terceros',
      'Panel web y app móvil completo',
      'Multi-ubicación',
      'Capacitación personalizada',
      'Soporte dedicado',
    ],
  },
  {
    id: 'ultra',
    code: 'ultra',
    name: 'Enterprise',
    subtitle: 'Ultra',
    monthlyPrice: 80,
    annualPrice: 850,
    screens: '20 pantallas',
    features: [
      'Hasta 20 pantallas',
      'Contenido publicitario',
      'Sin publicidad de terceros',
      'Panel web y app móvil completo',
      'Multi-ubicación',
      'Capacitación personalizada',
      'Soporte dedicado',
    ],
  },
  {
    id: 'empresarial',
    code: 'empresarial',
    name: 'Pantallas Gigantes',
    subtitle: 'Empresarial',
    monthlyPrice: null,
    annualPrice: null,
    screens: 'Ilimitadas',
    features: [
      'Pantallas de exterior a gran formato',
      'Pantallas LED gigantes',
      'Instalación on-premise',
      'Multi-ubicación',
      'Capacitación personalizada',
      'Soporte dedicado',
    ],
  },
];

export async function fetchPlans() {
  try {
    const res = await fetch(`${API_BASE}/api/plans`, { headers: { Accept: 'application/json' } });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    if (!Array.isArray(data) || data.length === 0) throw new Error('Sin planes');
    return data;
  } catch (err) {
    console.warn('No se pudieron cargar los planes desde el backend; usando fallback.', err);
    return FALLBACK_PLANS;
  }
}
