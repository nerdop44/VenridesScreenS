from odoo import models, fields, api
import logging

_logger = logging.getLogger(__name__)


class ResCurrencyRate(models.Model):
    _inherit = "res.currency.rate"

    @api.model
    def compute_rate(self, foreign_currency_id, rate_date):
        """
        Compute the rate and inverse rate for the given currency and date.

        If the foreign currency is USD then the rate will be the inverse company rate and the
        inverse rate will be the company rate, Else both rates will be the company rate.

        This is done because the foreign rate will be the rate that is gonna be shown to the user
        and the inverse rate will be the rate that will be used as factor to multiply for the
        computation of the foreign amounts.

        The logic is that if the foreign currency is VEF then we will be always multiplying by the
        value the user uses and see as the rate, but if the foreign currency is USD then we will be
        always multiplying by the inverse rate because the user will see the rate as the inverse
        rate.

        Parameters
        ----------
        foreign_currency_id : int
            The id of the foreign currency.
        rate_date : date
            The date of the rate that is gonna be searched for the given currency
            (foreign_currency_id).

        Returns
        -------
        dict
            A dictionary with the rate and inverse rate for the given currency and date.
        """
        rates = self.env["res.currency.rate"].search(
            [
                ("currency_id", "=", foreign_currency_id),
                ("company_id", "in", [self.env.company.id, False]),
                ("name", "<=", rate_date),
            ],
            order="name desc, id desc",
        )
        if not rates:
            currency = self.env["res.currency"].browse(foreign_currency_id)
            if self.env.company.currency_id.name == 'USD':
                return {
                    "foreign_rate": round(currency.rate, 4) if currency.rate else 1.0,
                    # BUG-020: la inversa NO se redondea a 4 decimales. Con base
                    # USD y una factura en VES, la inversa de 857.8876 es
                    # 0.001166; a 4 decimales queda 0.0012, un error del 2.9%
                    # que descuadra el asiento. La tasa visible si lleva 4
                    # decimales; el factor de calculo mantiene precision.
                    "foreign_inverse_rate": (1.0 / currency.rate) if currency.rate else 1.0,
                }
            else:
                return {
                    "foreign_rate": (1.0 / currency.inverse_rate) if currency.inverse_rate else 1.0,
                    "foreign_inverse_rate": currency.rate or 1.0,
                }

        # BUG-021: la busqueda es '<=' pero se tomaba 'rates[0]' sin orden,
        # que devolvia un registro arbitrario (el mas antiguo por id) en vez de
        # la ULTIMA tasa publicada hasta la fecha. Con el orden descendente
        # 'rates[:1]' es justamente la vigente, y el filtro por fecha exacta
        # deja de ser necesario.
        rate = rates[:1]
        company_currency = self.env.company.currency_id
        if company_currency.name == 'USD':
            return {
                "foreign_rate": round(rate.company_rate, 4),
                "foreign_inverse_rate": (1.0 / rate.company_rate) if rate.company_rate else 1.0,
            }
        else:
            return {
                "foreign_rate": round(rate.inverse_company_rate, 4),
                "foreign_inverse_rate": (1.0 / rate.inverse_company_rate) if rate.inverse_company_rate else 1.0,
            }

    @api.model
    def compute_inverse_rate(self, rate):
        """
        Compute the inverse rate for the given rate.
        The inverse rate will be the inverse of the given rate if the foreign currency is USD, else
        the inverse rate will be the same as the given rate.

        Parameters
        ----------
        rate : float
            The rate that is gonna be used to compute the inverse rate.

        Returns
        -------
        float
            The inverse rate for the given rate.
        """
        base_usd_id = self.env["ir.model.data"]._xmlid_to_res_id(
            "base.USD", raise_if_not_found=False
        )
        foreign_currency_id = self.env.company.currency_foreign_id.id or False
        # BUG-020: la tasa se redondea a 4 decimales (es el dato que ve y
        # digita el usuario), pero su inversa se conserva a precision plena.
        # Redondear 1/857.8876 a 4 decimales devolveria 0.0012 y moveria
        # cualquier total en un 2.9%.
        if foreign_currency_id == base_usd_id:
            inverse_rate = (1.0 / rate) if rate else 1.0
        else:
            inverse_rate = round(rate, 4)
        return inverse_rate
