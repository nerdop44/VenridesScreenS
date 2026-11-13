# LocVe — utilidades internas del modulo de contactos.
# Se vendoriza la consulta al CNE para que el modulo no dependa del paquete
# `odoo.addons.tools` del repositorio de desarrollo.
from . import locve_cne_query

binaural_cne_query = locve_cne_query
