/**
 * Configuración pública del sitio.
 * Datos fiscales y de contacto confirmados por el titular (noviembre 2026).
 */
export const site = {
  brand: 'VScreenS',
  domain: 'vscreens.inverpave.com',
  landingUrl: import.meta.env.VITE_LANDING_URL || 'https://vscreens.inverpave.com',
  appUrl: import.meta.env.VITE_ADMIN_PANEL_URL || 'https://vscreens-app.inverpave.com',
  apiUrl: import.meta.env.VITE_API_BASE_URL || 'https://vscreens-api.inverpave.com',
  tvUrl: import.meta.env.VITE_TV_URL || 'https://vscreens-tv.inverpave.com',
  odooUrl: import.meta.env.VITE_ODOO_URL || 'https://vscreens-erp.inverpave.com',

  // Titular del servicio (firma personal).
  legalName: 'Inversiones Pulido Aguirre INVERPA',
  legalForm: 'Firma Personal',
  commercialName: 'VScreenS',
  rif: 'V-14304044-1',
  address: 'Urb. La Cardenera, Olivos 719, Barinas',
  country: 'Venezuela',
  jurisdiction: 'República Bolivariana de Venezuela',

  // Contactos.
  contactEmail: 'info.vscreens@inverpave.com',
  billingEmail: 'pagos.vscreens@inverpave.com',
  privacyEmail: 'privacidad.vscreens@inverpave.com',
  securityEmail: 'seguridad.vscreens@inverpave.com',
  phone: '+58 414-5694075',
  whatsapp: '+58 414-5694075',
  whatsappLink: 'https://wa.me/584145694075',

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
