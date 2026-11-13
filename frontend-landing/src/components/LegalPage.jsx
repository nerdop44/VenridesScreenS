import React from 'react';
import { site } from '../config/site';

const Section = ({ title, children }) => (
  <section className="mb-10">
    <h2 className="text-xl md:text-2xl font-bold text-white mb-4">{title}</h2>
    <div className="space-y-4 text-slate-300 font-light leading-relaxed">{children}</div>
  </section>
);

const List = ({ items }) => (
  <ul className="list-disc pl-6 space-y-2">
    {items.map((item, i) => <li key={i}>{item}</li>)}
  </ul>
);

const legalContent = {
  'aviso-legal': {
    title: 'Aviso legal',
    intro: `Este aviso legal regula el acceso y uso del sitio web ${site.domain} y de los servicios digitales de ${site.commercialName}.`,
    sections: (
      <>
        <Section title="1. Titular del sitio">
          <p><strong>Titular:</strong> {site.legalName} ({site.legalForm})</p>
          <p><strong>Nombre comercial:</strong> {site.commercialName}</p>
          <p><strong>RIF:</strong> {site.rif}</p>
          <p><strong>Domicilio:</strong> {site.address}, {site.country}</p>
          <p><strong>Teléfono / WhatsApp:</strong> {site.phone}</p>
          <p><strong>Correo de contacto:</strong> <a className="text-primary" href={`mailto:${site.contactEmail}`}>{site.contactEmail}</a></p>
        </Section>
        <Section title="2. Objeto">
          <p>El sitio tiene por objeto informar sobre los servicios de señalización digital, gestión de pantallas, contenido y publicidad de {site.commercialName}, así como permitir la solicitud de información, la contratación de planes y el acceso al panel de clientes.</p>
        </Section>
        <Section title="3. Propiedad intelectual e industrial">
          <p>Los textos, imágenes, logotipos, software, diseño, estructura y demás contenidos del sitio son titularidad de {site.legalName} o de terceros que han autorizado su uso. Queda prohibida su reproducción, distribución, comunicación pública o transformación sin autorización previa y por escrito.</p>
        </Section>
        <Section title="4. Responsabilidad">
          <p>El titular adopta medidas razonables para mantener la información actualizada y el sitio disponible, pero no garantiza la ausencia de interrupciones, errores o contenidos de terceros. El uso del sitio y de los servicios se realiza bajo la responsabilidad del usuario, sin perjuicio de los derechos que le reconoce la ley.</p>
        </Section>
        <Section title="5. Enlaces">
          <p>El sitio puede contener enlaces a plataformas de terceros (por ejemplo, YouTube, Google Drive o pasarelas de pago). El titular no controla ni responde por sus contenidos, políticas o prácticas.</p>
        </Section>
        <Section title="6. Legislación aplicable">
          <p>Este aviso se rige por las leyes de {site.jurisdiction}. Cualquier controversia se someterá a los tribunales competentes de {site.jurisdiction}, salvo norma imperativa en contrario.</p>
        </Section>
      </>
    ),
  },

  terminos: {
    title: 'Términos y condiciones',
    intro: `Estos términos regulan el uso de la plataforma ${site.commercialName}, el panel de clientes, la aplicación para TV y los servicios asociados.`,
    sections: (
      <>
        <Section title="1. Aceptación">
          <p>Al registrarse, contratar un plan o utilizar la plataforma, el cliente acepta estos términos. Si no está de acuerdo, debe abstenerse de usar el servicio.</p>
        </Section>
        <Section title="2. Descripción del servicio">
          <p>{site.commercialName} es una plataforma de gestión de pantallas digitales que permite administrar contenido, reproducción, branding, alertas, usuarios y pantallas desde un panel web y una aplicación para TV.</p>
        </Section>
        <Section title="3. Registro y seguridad de la cuenta">
          <List items={[
            'El cliente debe proporcionar información veraz y mantenerla actualizada.',
            'Las credenciales son personales e intransferibles.',
            'El cliente es responsable de las acciones realizadas con su cuenta y de la seguridad de sus dispositivos.',
            'El titular puede suspender cuentas ante indicios de fraude, abuso o incumplimiento.',
          ]} />
        </Section>
        <Section title="4. Planes, precios y pagos">
          <List items={[
            'Los planes, límites, precios y funciones vigentes se publican en el sitio y en el panel de administración.',
            'Los precios se expresan en dólares estadounidenses (USD), salvo indicación expresa. Los pagos en bolívares se calculan según la tasa BCV aplicable, cuando corresponda.',
            'La contratación, renovación y cancelación se rigen por el plan adquirido y por la política de devoluciones y cancelaciones.',
            'El impago o la falta de renovación puede provocar la suspensión del servicio y, eventualmente, la eliminación de los datos conforme a la política de conservación.',
          ]} />
        </Section>
        <Section title="5. Uso aceptable">
          <List items={[
            'No publicar contenido ilícito, discriminatorio, violento, sexual, engañoso o que vulnere derechos de terceros.',
            'No utilizar el servicio para spam, minería, criptomonedas, malware, phishing o actividades fraudulentas.',
            'No intentar acceder a cuentas, datos o infraestructura de otros clientes.',
            'No eludir límites de pantallas, planes o medidas de seguridad.',
            'Respetar los derechos de autor, marcas y licencias del contenido reproducido.',
          ]} />
        </Section>
        <Section title="6. Contenido del cliente">
          <p>El cliente conserva la titularidad de sus contenidos y concede al titular una licencia limitada para alojarlos, reproducirlos y mostrarlos con la única finalidad de prestar el servicio. El cliente declara contar con los derechos y autorizaciones necesarios.</p>
        </Section>
        <Section title="7. Disponibilidad y soporte">
          <p>El titular procurará una disponibilidad razonable del servicio, pero no garantiza una disponibilidad ininterrumpida. El soporte se presta por los canales publicados y según el nivel del plan contratado. Las interrupciones programadas se comunicarán cuando sea posible.</p>
        </Section>
        <Section title="8. Suspensión y cancelación">
          <List items={[
            'El titular puede suspender el servicio por impago, uso indebido, riesgo de seguridad o requerimiento legal.',
            'El cliente puede cancelar su suscripción desde el panel o solicitándolo por escrito.',
            'La cancelación no genera reembolsos automáticos; se aplica la política de devoluciones y cancelaciones.',
            'Tras la cancelación, los datos podrán conservarse durante el plazo necesario para obligaciones legales y luego eliminarse.',
          ]} />
        </Section>
        <Section title="9. Limitación de responsabilidad">
          <p>En la medida permitida por la ley, el titular no responde por daños indirectos, lucro cesante, pérdida de datos por causas ajenas a su control, interrupciones de Internet, fallos de dispositivos del cliente o contenidos de terceros. Nada en estos términos limita derechos irrenunciables del consumidor.</p>
        </Section>
        <Section title="10. Modificaciones y ley aplicable">
          <p>El titular puede actualizar estos términos publicando la nueva versión en el sitio. El uso continuado después de la actualización implica aceptación. Se rigen por las leyes de {site.jurisdiction}.</p>
        </Section>
      </>
    ),
  },

  privacidad: {
    title: 'Política de privacidad',
    intro: `Esta política explica qué datos personales tratamos, con qué finalidad, durante cuánto tiempo y cómo puede ejercer sus derechos.`,
    sections: (
      <>
        <Section title="1. Responsable del tratamiento">
          <p>{site.legalName}, RIF {site.rif}, domicilio {site.address}, {site.country}. Contacto de privacidad: <a className="text-primary" href={`mailto:${site.privacyEmail}`}>{site.privacyEmail}</a>.</p>
        </Section>
        <Section title="2. Datos que tratamos">
          <List items={[
            'Datos de identificación y contacto: nombre, empresa, correo, teléfono, RIF y dirección.',
            'Datos de cuenta: usuario, rol, credenciales cifradas y preferencias.',
            'Datos de facturación y pagos: plan, importe, moneda, método y referencia.',
            'Datos de uso: pantallas vinculadas, contenido configurado, alertas, tickets y registros de actividad.',
            'Datos técnicos: dirección IP, tipo de dispositivo, navegador, fecha y hora de acceso.',
            'Datos analíticos del sitio: páginas visitadas, referente y tipo de dispositivo, con IP seudonimizada.',
            'Datos de soporte: conversaciones, adjuntos y solicitudes.',
          ]} />
        </Section>
        <Section title="3. Finalidades y bases de tratamiento">
          <List items={[
            'Prestar el servicio, gestionar la cuenta y las pantallas (ejecución del contrato).',
            'Facturar, cobrar y gestionar renovaciones (ejecución del contrato y obligaciones legales).',
            'Atender soporte y responder consultas (ejecución del contrato o interés legítimo).',
            'Enviar comunicaciones operativas y de seguridad (ejecución del contrato).',
            'Enviar comunicaciones comerciales cuando exista consentimiento o base legal aplicable.',
            'Medir el uso del sitio y mejorar el servicio (consentimiento para cookies analíticas).',
            'Prevenir fraude, abuso y riesgos de seguridad (interés legítimo y obligaciones legales).',
          ]} />
        </Section>
        <Section title="4. Conservación">
          <p>Conservamos los datos durante la relación contractual y los plazos necesarios para obligaciones legales, contables, fiscales y de defensa. Los datos de analítica se conservan de forma agregada o seudonimizada y se eliminan o anonimizan cuando dejan de ser necesarios.</p>
        </Section>
        <Section title="5. Destinatarios y encargados">
          <List items={[
            'Proveedores de infraestructura, alojamiento y respaldo.',
            'Proveedores de correo electrónico y comunicaciones.',
            'Proveedores de analítica y servicios de Google (YouTube/Drive) cuando el cliente los utiliza.',
            'Asesores legales, contables y autoridades cuando exista obligación legal.',
          ]} />
          <p>Los encargados actúan bajo instrucciones y obligaciones de confidencialidad y seguridad. Algunos pueden estar ubicados fuera de Venezuela; en tal caso se adoptan salvaguardas razonables.</p>
        </Section>
        <Section title="6. Derechos del titular">
          <p>El titular puede solicitar acceso, rectificación, actualización, supresión, oposición, limitación y portabilidad de sus datos, así como retirar su consentimiento, escribiendo a <a className="text-primary" href={`mailto:${site.privacyEmail}`}>{site.privacyEmail}</a>. Responderemos en el plazo legal aplicable. También puede presentar una reclamación ante la autoridad competente.</p>
        </Section>
        <Section title="7. Seguridad">
          <p>Aplicamos medidas técnicas y organizativas razonables: cifrado en tránsito, control de acceso, contraseñas cifradas, respaldos, registro de actividad y separación de entornos. Ningún sistema es totalmente infalible; si ocurre un incidente relevante, actuaremos conforme a la ley y comunicaremos lo necesario.</p>
        </Section>
        <Section title="8. Menores y terceros">
          <p>El servicio está dirigido a empresas y personas mayores de edad. No recopilamos intencionalmente datos de menores. El cliente debe contar con base legal para tratar datos de terceros que incorpore a la plataforma.</p>
        </Section>
        <Section title="9. Cambios">
          <p>Podemos actualizar esta política. Publicaremos la versión vigente con su fecha de actualización. Si el cambio es sustancial, lo comunicaremos por los canales habituales.</p>
        </Section>
      </>
    ),
  },

  cookies: {
    title: 'Política de cookies',
    intro: `Esta política describe las cookies y tecnologías similares que utiliza ${site.domain}.`,
    sections: (
      <>
        <Section title="1. ¿Qué son las cookies?">
          <p>Son pequeños archivos que se almacenan en el navegador y permiten recordar preferencias, mantener la sesión y obtener información estadística. También usamos almacenamiento local del navegador para preferencias y consentimiento.</p>
        </Section>
        <Section title="2. Tipos de cookies">
          <List items={[
            'Necesarias: permiten el funcionamiento básico, la seguridad y la sesión. No requieren consentimiento cuando son imprescindibles.',
            'De preferencias: recuerdan idioma, tema o consentimiento de cookies.',
            'Analíticas: miden visitas, páginas y dispositivos para mejorar el sitio. Se activan solo con consentimiento.',
            'De terceros: pueden ser establecidas por YouTube, Google u otros servicios incrustados cuando el usuario interactúa con ellos.',
          ]} />
        </Section>
        <Section title="3. Cookies y almacenamiento que usamos">
          <List items={[
            '`vscreens_cookie_consent`: guarda la decisión del usuario sobre cookies (necesaria).',
            '`token`, `user`, `user_role`: mantienen la sesión del panel de clientes (necesarias).',
            'Analítica propia: registra visitas con IP seudonimizada y datos agregados (solo con consentimiento).',
            'YouTube/Google: cookies de terceros cuando se reproduce o incrusta contenido (gestionadas por dichos proveedores).',
          ]} />
        </Section>
        <Section title="4. Consentimiento y gestión">
          <p>Al ingresar al sitio mostramos un aviso de cookies. Puede aceptar todas, rechazar las no necesarias o configurar sus preferencias. También puede borrar o bloquear cookies desde la configuración de su navegador; algunas funciones podrían dejar de funcionar.</p>
        </Section>
        <Section title="5. Actualizaciones">
          <p>Esta política puede actualizarse cuando cambien las cookies o la normativa aplicable. La fecha de última actualización se indica al final del documento.</p>
        </Section>
      </>
    ),
  },

  devoluciones: {
    title: 'Política de devoluciones y cancelaciones',
    intro: `Esta política regula la cancelación de suscripciones y las devoluciones de pagos de ${site.commercialName}.`,
    sections: (
      <>
        <Section title="1. Naturaleza del servicio">
          <p>Los planes son servicios digitales de acceso continuo. La contratación habilita el uso de la plataforma y no implica la venta de software perpetuo, salvo pacto escrito.</p>
        </Section>
        <Section title="2. Cancelación por el cliente">
          <List items={[
            'El cliente puede solicitar la cancelación desde el panel o por escrito a ' + site.billingEmail + '.',
            'La cancelación detiene la renovación siguiente; el acceso se mantiene hasta el final del período ya pagado, salvo incumplimiento.',
            'No se generan reembolsos por períodos parciales ya iniciados, salvo lo exigido por la ley o lo acordado por escrito.',
          ]} />
        </Section>
        <Section title="3. Devoluciones">
          <List items={[
            'Las solicitudes de devolución se evalúan caso por caso y deben presentarse dentro de los primeros 7 días desde el pago, salvo norma imperativa en contrario.',
            'No se reembolsan servicios ya prestados, personalizaciones, instalaciones, capacitaciones ni trabajos ejecutados.',
            'Los reembolsos aprobados se realizan por el mismo medio de pago o por el medio que acuerden las partes, en un plazo razonable.',
            'Los costos de transferencia, comisiones bancarias o de pasarela pueden descontarse cuando la ley lo permita.',
          ]} />
        </Section>
        <Section title="4. Suspensión por impago">
          <p>Si no se recibe el pago de renovación, el servicio puede suspenderse. La reactivación puede requerir el pago de importes pendientes y una penalidad administrativa razonable, si está prevista en el plan.</p>
        </Section>
        <Section title="5. Cómo solicitar una devolución">
          <p>Escribe a <a className="text-primary" href={`mailto:${site.billingEmail}`}>{site.billingEmail}</a> indicando empresa, correo de la cuenta, fecha e importe del pago, método de pago y motivo. Conserva el comprobante.</p>
        </Section>
        <Section title="6. Excepciones">
          <p>No proceden devoluciones en casos de uso indebido, incumplimiento de términos, fraude, contenido ilícito o cuando el servicio se haya consumido sustancialmente, sin perjuicio de los derechos irrenunciables del consumidor.</p>
        </Section>
      </>
    ),
  },

  seguridad: {
    title: 'Seguridad de la información',
    intro: `Resumen de las medidas y canales de reporte de seguridad de ${site.commercialName}.`,
    sections: (
      <>
        <Section title="1. Medidas técnicas y organizativas">
          <List items={[
            'Cifrado en tránsito mediante HTTPS/TLS.',
            'Contraseñas almacenadas con funciones de hash seguras.',
            'Control de acceso por roles y separación de permisos.',
            'Registro de actividad y auditoría de operaciones sensibles.',
            'Respaldos periódicos y pruebas de restauración.',
            'Actualizaciones de seguridad y revisión de dependencias.',
            'Monitoreo de disponibilidad y alertas operativas.',
          ]} />
        </Section>
        <Section title="2. Responsabilidades del cliente">
          <List items={[
            'Usar contraseñas robustas y no compartirlas.',
            'Mantener actualizados los dispositivos y navegadores.',
            'Proteger el acceso físico a las pantallas y equipos.',
            'Revisar periódicamente los usuarios y permisos.',
            'Reportar de inmediato cualquier acceso no autorizado.',
          ]} />
        </Section>
        <Section title="3. Reporte de vulnerabilidades">
          <p>Si detectas una vulnerabilidad o incidente, escríbenos a <a className="text-primary" href={`mailto:${site.securityEmail}`}>{site.securityEmail}</a> con una descripción y pasos de reproducción. Solicitamos no divulgar públicamente el hallazgo antes de que podamos corregirlo.</p>
        </Section>
        <Section title="4. Incidentes">
          <p>Investigaremos los incidentes, aplicaremos medidas de contención y, cuando corresponda, notificaremos a los afectados y a las autoridades conforme a la ley aplicable.</p>
        </Section>
      </>
    ),
  },
};

export default function LegalPage({ slug }) {
  const content = legalContent[slug];
  if (!content) return null;

  return (
    <main className="pt-32 pb-24 bg-black min-h-screen">
      <div className="max-w-4xl mx-auto px-6">
        <a href="/" className="inline-flex items-center gap-2 text-primary font-mono text-xs uppercase tracking-widest mb-8 hover:underline">
          <span className="material-symbols-outlined text-base">arrow_back</span>
          Volver al inicio
        </a>

        <p className="font-mono text-xs uppercase tracking-[0.25em] text-primary mb-3">Legal</p>
        <h1 className="text-4xl md:text-6xl font-black uppercase italic leading-none mb-6">{content.title}</h1>
        <p className="text-slate-400 text-lg font-light leading-relaxed mb-12">{content.intro}</p>

        <div className="glass rounded-3xl p-6 md:p-10 border border-white/10">
          {content.sections}
        </div>

        <div className="mt-8 text-xs text-slate-500 font-mono leading-relaxed space-y-2">
          <p>Última actualización: {site.legalUpdatedAt}.</p>
          <p>Contacto: <a className="text-primary" href={`mailto:${site.contactEmail}`}>{site.contactEmail}</a> · {site.legalName} · RIF {site.rif}</p>
          <p>Este documento es una base informativa y debe ser revisado por asesoría legal antes de su publicación definitiva.</p>
        </div>
      </div>
    </main>
  );
}
