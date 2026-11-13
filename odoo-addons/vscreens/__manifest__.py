{
    "name": "VScreenS — Señalización digital",
    "version": "20.0.1.0.0",
    "category": "Services/Digital Signage",
    "summary": "Gestión de empresas, pantallas, contenido, planes y suscripciones de VScreenS",
    "description": """
Módulo de gestión de la plataforma VScreenS sobre Odoo 20 CE.

Incluye:
- Empresas/clientes, planes y límites configurables.
- Pantallas (dispositivos) y códigos de vinculación.
- Contenido, branding, publicidad global y alertas.
- Pagos, mensajería, helpdesk, CRM y analítica.
- API REST compatible con el panel del cliente y la app de TV.
""",
    "author": "Inverpave / VScreenS",
    "website": "https://vscreens.inverpave.com",
    "license": "OPL-1",
    "depends": [
        "base",
        "mail",
        "web",
        "calendar",
        "crm",
        "account",
        "l10n_ve",
    ],
    "data": [
        "security/groups.xml",
        "security/ir.access.csv",
        "data/plans.xml",
        "data/products.xml",
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
        "views/email_template_views.xml",
        "views/promotion_views.xml",
        "views/affiliate_views.xml",
        "views/calendar_activity_views.xml",
        "views/free_plan_usage_views.xml",
        "data/cron_views.xml",
    ],
    "assets": {
        "web.assets_backend": [
            "vscreens/static/src/scss/vscreens.scss",
            "vscreens/static/src/js/vscreens_fields.js",
            "vscreens/static/src/xml/vscreens_fields.xml",
        ],
        "web.assets_frontend": [
            "vscreens/static/src/js/benry_widget.js",
        ],
    },
    "installable": True,
    "application": True,
    "auto_install": False,
    "post_init_hook": "vscreens.hooks.post_init_hook",
}
