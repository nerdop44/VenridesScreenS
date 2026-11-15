import React, { useEffect } from 'react';
import { site } from '../config/site';

/**
 * Componente SEO reutilizable para VScreenS.
 * Gestiona dinámicamente:
 *  - <title>
 *  - <meta name="description">
 *  - Open Graph (og:*)
 *  - Twitter Card (twitter:*)
 *  - Canonical URL
 *  - JSON-LD (Organization, WebSite, BreadcrumbList si aplica)
 *
 * @param {Object} props
 * @param {string} props.title - Título de la página (se le añade " | VScreenS")
 * @param {string} props.description - Meta descripción
 * @param {string} props.image - URL de la imagen og:image y twitter:image
 * @param {string} props.url - Ruta canónica relativa (ej. "/", "/aviso-legal")
 * @param {string} props.type - og:type (default "website")
 * @param {Array} props.breadcrumbs - Array de { label, href } para BreadcrumbList JSON-LD
 * @param {Object} props.extraJsonLd - JSON-LD adicional por página
 */
const SEO = ({
  title = null,
  description = null,
  image = null,
  url = '/',
  type = 'website',
  breadcrumbs = null,
  extraJsonLd = null,
}) => {
  const fullTitle = title
    ? `${title} | ${site.brand}`
    : `${site.brand} | Pantallas inteligentes para tu negocio`;

  const fullDescription =
    description ||
    'Plataforma de señalización digital para gestionar pantallas, contenido, publicidad y alertas desde un solo panel.';

  const canonicalUrl = `${site.landingUrl}${url}`;
  const ogImage = image || `${site.landingUrl}/vscreens_logo.png`;
  const siteName = site.brand;

  // JSON-LD: Organization
  const organizationJsonLd = {
    '@context': 'https://schema.org',
    '@type': 'Organization',
    name: site.brand,
    legalName: site.legalName,
    url: site.landingUrl,
    logo: `${site.landingUrl}/vscreens_logo.png`,
    email: site.contactEmail,
    telephone: site.phone,
    address: {
      '@type': 'PostalAddress',
      streetAddress: site.address,
      addressLocality: 'Barinas',
      addressRegion: 'Barinas',
      addressCountry: site.country,
    },
    contactPoint: [
      {
        '@type': 'ContactPoint',
        contactType: 'customer support',
        telephone: site.phone,
        email: site.contactEmail,
        availableLanguage: ['Spanish'],
      },
    ],
    sameAs: [site.whatsappLink],
  };

  // JSON-LD: WebSite
  const websiteJsonLd = {
    '@context': 'https://schema.org',
    '@type': 'WebSite',
    name: site.brand,
    url: site.landingUrl,
    potentialAction: {
      '@type': 'SearchAction',
      target: `${site.landingUrl}/buscar?q={search_term_string}`,
      'query-input': 'required name=search_term_string',
    },
  };

  // JSON-LD: BreadcrumbList (solo si se proveen breadcrumbs)
  const breadcrumbJsonLd = breadcrumbs
    ? {
        '@context': 'https://schema.org',
        '@type': 'BreadcrumbList',
        itemListElement: breadcrumbs.map((crumb, index) => ({
          '@type': 'ListItem',
          position: index + 1,
          name: crumb.label,
          item: crumb.href ? `${site.landingUrl}${crumb.href}` : canonicalUrl,
        })),
      }
    : null;

  useEffect(() => {
    // --- <title> ---
    document.title = fullTitle;

    // --- <meta name="description"> ---
    setMeta('description', fullDescription);
    setMeta('robots', 'index,follow');

    // --- Open Graph ---
    setProperty('og:type', type);
    setProperty('og:url', canonicalUrl);
    setProperty('og:title', fullTitle);
    setProperty('og:description', fullDescription);
    setProperty('og:image', ogImage);
    setProperty('og:image:width', '1200');
    setProperty('og:image:height', '630');
    setProperty('og:site_name', siteName);
    setProperty('og:locale', 'es_VE');

    // --- Twitter Card ---
    setMeta('twitter:card', 'summary_large_image');
    setMeta('twitter:title', fullTitle);
    setMeta('twitter:description', fullDescription);
    setMeta('twitter:image', ogImage);

    // --- Canonical URL ---
    setCanonical(canonicalUrl);

    // --- JSON-LD ---
    setJsonLd([
      organizationJsonLd,
      websiteJsonLd,
      breadcrumbJsonLd,
      extraJsonLd,
    ].filter(Boolean));
  }, [
    fullTitle,
    fullDescription,
    canonicalUrl,
    ogImage,
    siteName,
    type,
    organizationJsonLd,
    websiteJsonLd,
    breadcrumbJsonLd,
    extraJsonLd,
  ]);

  return null;
};

/**
 * Establece o actualiza un meta[name="..."]
 */
function setMeta(name, content) {
  let el = document.querySelector(`meta[name="${name}"]`);
  if (!el) {
    el = document.createElement('meta');
    el.setAttribute('name', name);
    document.head.appendChild(el);
  }
  el.setAttribute('content', content);
}

/**
 * Establece o actualiza un meta[property="..."]
 */
function setProperty(property, content) {
  let el = document.querySelector(`meta[property="${property}"]`);
  if (!el) {
    el = document.createElement('meta');
    el.setAttribute('property', property);
    document.head.appendChild(el);
  }
  el.setAttribute('content', content);
}

/**
 * Establece o actualiza el link[rel="canonical"]
 */
function setCanonical(href) {
  let el = document.querySelector('link[rel="canonical"]');
  if (!el) {
    el = document.createElement('link');
    el.setAttribute('rel', 'canonical');
    document.head.appendChild(el);
  }
  el.setAttribute('href', href);
}

/**
 * Inyecta scripts JSON-LD en <head>, eliminando los previos marcados con data-seo
 */
function setJsonLd(array) {
  document
    .querySelectorAll('script[type="application/ld+json"][data-seo]')
    .forEach((el) => el.remove());

  array.forEach((data) => {
    const script = document.createElement('script');
    script.type = 'application/ld+json';
    script.setAttribute('data-seo', 'true');
    script.textContent = JSON.stringify(data);
    document.head.appendChild(script);
  });
}

export default SEO;
