{
    "name": "VenridesScreenS — Señalización digital",
    "version": "20.0.1.0.0",
    "category": "Services/Digital Signage",
    "summary": "Gestión de empresas, pantallas, contenido, planes y suscripciones de VenridesScreenS",
    "description": """
Módulo de gestión de la plataforma VenridesScreenS sobre Odoo 20 CE.

Incluye:
- Empresas/clientes, planes y límites configurables.
- Pantallas (dispositivos) y códigos de vinculación.
- Contenido, branding, publicidad global y alertas.
- Pagos, mensajería, helpdesk, CRM y analítica.
- API REST compatible con el panel del cliente y la app de TV.
""",
    "author": "Inverpave / VenridesScreenS",
    "website": "https://venrides.inverpave.com",
    "license": "OPL-1",
    "depends": [
        "base",
        "mail",
        "web",
        "calendar",
        "crm",
    ],
    "data": [
        "security/groups.xml",
        "security/ir.access.csv",
        "data/plans.xml",
        "data/global_ad.xml",
        "data/cron.xml",
        "views/plan_views.xml",
        "views/company_views.xml",
        "views/device_views.xml",
        "views/payment_views.xml",
        "views/content_views.xml",
        "views/message_views.xml",
        "views/ticket_views.xml",
        "views/crm_views.xml",
        "views/analytics_views.xml",
        "views/dashboard.xml",
        "views/menus.xml",
    ],
    "assets": {
        "web.assets_backend": [
            "venrides_screens/static/src/scss/venrides.scss",
        ],
    },
    "installable": True,
    "application": True,
    "auto_install": False,
}
