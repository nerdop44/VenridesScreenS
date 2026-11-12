from odoo import fields, models


class CrmLead(models.Model):
    _inherit = "crm.lead"

    venrides_plan_interest = fields.Char(string="Plan de interés")
    venrides_source_detail = fields.Char(string="Origen VenridesScreenS")
    venrides_contact_name = fields.Char(string="Nombre de contacto VenridesScreenS")
