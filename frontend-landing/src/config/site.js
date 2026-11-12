/**
 * Configuración pública del sitio.
 * Los datos marcados como [COMPLETAR] deben confirmarse antes de producción.
 */
export const site = {
  brand: 'VenridesScreenS',
  domain: 'venrides.inverpave.com',
  landingUrl: import.meta.env.VITE_LANDING_URL || 'https://venrides.inverpave.com',
  appUrl: import.meta.env.VITE_ADMIN_PANEL_URL || 'https://venrides-app.inverpave.com',
  apiUrl: import.meta.env.VITE_API_BASE_URL || 'https://venrides-api.inverpave.com',
  tvUrl: import.meta.env.VITE_TV_URL || 'https://venrides-tv.inverpave.com',
  odooUrl: import.meta.env.VITE_ODOO_URL || 'https://venrides-erp.inverpave.com',

  // Titular del servicio. [COMPLETAR / CONFIRMAR]
  legalName: 'Inverpave, C.A.',
  commercialName: 'VenridesScreenS',
  rif: '[COMPLETAR RIF]',
  address: '[COMPLETAR DOMICILIO FISCAL]',
  country: 'Venezuela',
  jurisdiction: 'República Bolivariana de Venezuela',

  // Contactos. [CONFIRMAR BUZONES]
  contactEmail: 'soporte@inverpave.com',
  billingEmail: 'pagos@inverpave.com',
  privacyEmail: 'privacidad@inverpave.com',
  securityEmail: 'seguridad@inverpave.com',
  phone: '[COMPLETAR TELÉFONO]',
  whatsapp: '[COMPLETAR WHATSAPP]',

  // Fecha de última actualización de los documentos legales.
  legalUpdatedAt: '12 de noviembre de 2026',
};

export const legalLinks = [
  { href: '/aviso-legal', label: 'Aviso legal' },
  { href: '/terminos', label: 'Términos y condiciones' },
  { href: '/privacidad', label: 'Política de privacidad' },
  { href: '/cookies', label: 'Política de cookies' },
  { href: '/devoluciones', label: 'Devoluciones y cancelaciones' },
  { href: '/seguridad', label: 'Seguridad' },
];
