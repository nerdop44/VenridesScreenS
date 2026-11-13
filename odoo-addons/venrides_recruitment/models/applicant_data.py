# -*- coding: utf-8 -*-
from odoo import fields, models


class VenridesApplicantEducation(models.Model):
    _name = 'venrides.applicant.education'
    _description = 'Formación académica del postulante'
    _order = 'date_end desc, id desc'

    applicant_id = fields.Many2one(
        'hr.applicant', string='Postulante', required=True, ondelete='cascade')
    institution = fields.Char(string='Institución', required=True)
    degree = fields.Char(string='Título obtenido')
    level = fields.Selection([
        ('primary', 'Primaria'),
        ('secondary', 'Bachiller'),
        ('technical', 'Técnico medio'),
        ('university', 'Universitario'),
        ('postgraduate', 'Postgrado'),
        ('course', 'Curso / taller'),
    ], string='Nivel', default='secondary')
    date_start = fields.Date(string='Desde')
    date_end = fields.Date(string='Hasta')
    current = fields.Boolean(string='En curso')
    notes = fields.Text(string='Notas')


class VenridesApplicantExperience(models.Model):
    _name = 'venrides.applicant.experience'
    _description = 'Experiencia laboral del postulante'
    _order = 'date_end desc, id desc'

    applicant_id = fields.Many2one(
        'hr.applicant', string='Postulante', required=True, ondelete='cascade')
    company = fields.Char(string='Empresa', required=True)
    position = fields.Char(string='Cargo', required=True)
    location = fields.Char(string='Ubicación')
    phone = fields.Char(string='Teléfono de la empresa')
    contact_name = fields.Char(string='Persona de contacto')
    date_start = fields.Date(string='Desde')
    date_end = fields.Date(string='Hasta')
    current = fields.Boolean(string='Trabajo actual')
    functions = fields.Text(string='Funciones')
    reason_leave = fields.Char(string='Motivo de salida')


class VenridesApplicantReference(models.Model):
    _name = 'venrides.applicant.reference'
    _description = 'Referencia personal o laboral'
    _order = 'ref_type, id'

    applicant_id = fields.Many2one(
        'hr.applicant', string='Postulante', required=True, ondelete='cascade')
    ref_type = fields.Selection([
        ('personal', 'Personal'),
        ('labor', 'Laboral'),
    ], string='Tipo', required=True, default='personal')
    name = fields.Char(string='Nombre y apellido', required=True)
    relationship = fields.Char(string='Parentesco / relación')
    company = fields.Char(string='Empresa / ubicación')
    position = fields.Char(string='Cargo')
    phone = fields.Char(string='Teléfono', required=True)
    email = fields.Char(string='Correo')
    years_known = fields.Char(string='Tiempo de conocerse')
    work_period = fields.Char(string='Tiempo de trabajo')
    verified = fields.Boolean(string='Verificada')
    verification_date = fields.Date(string='Fecha de verificación')
    notes = fields.Text(string='Notas')
