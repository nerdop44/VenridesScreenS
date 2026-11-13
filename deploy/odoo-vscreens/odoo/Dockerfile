# Imagen de Odoo para VScreenS, derivada de la imagen oficial 20.0.
#
# La imagen oficial ya incluye psycopg2, lxml, wkhtmltopdf, requests, bs4,
# xlsxwriter, dateutil y pytz. Solo faltan numpy/pandas para las exportaciones
# XLSX de retenciones municipales de LocVe (mismo criterio que la imagen del
# café, venrides-odoo:20.0).
#
# Se instalan con --no-deps a proposito: si se deja que pip resuelva pandas,
# actualiza pytz y rompe el arranque del core de Odoo.
FROM odoo:20.0

USER root
RUN pip install --no-cache-dir --break-system-packages --no-deps \
        "numpy==1.26.4" \
        "pandas==2.2.3"

USER odoo
