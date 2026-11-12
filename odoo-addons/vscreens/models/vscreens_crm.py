from odoo import fields, models


class CrmLead(models.Model):
    _inherit = "crm.lead"

    vscreens_plan_interest = fields.Char(string="Plan de interés")
    vscreens_source_detail = fields.Char(string="Origen VScreenS")
    vscreens_contact_name = fields.Char(string="Nombre de contacto VScreenS")
