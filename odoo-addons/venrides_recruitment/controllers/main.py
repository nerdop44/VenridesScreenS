# -*- coding: utf-8 -*-
import base64
import io
import secrets
from datetime import datetime

from PIL import Image

from odoo import fields, http
from odoo.http import request

MAX_CV_SIZE = 5 * 1024 * 1024  # 5 MB


def _clean(value):
    return (value or '').strip()


def _to_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _to_date(value):
    value = _clean(value)
    if not value:
        return False
    try:
        return datetime.strptime(value, '%Y-%m-%d').date()
    except ValueError:
        return False


class VenridesRecruitmentController(http.Controller):

    # ------------------------------------------------------------------
    # Vacantes y formulario público
    # ------------------------------------------------------------------
    @http.route('/empleo', type='http', auth='public', website=True, sitemap=True)
    def vacancy_list(self, **kwargs):
        vacancies = request.env['venrides.vacancy'].sudo().search([
            ('state', '=', 'open'),
        ])
        return request.render('venrides_recruitment.vacancy_list', {
            'vacancies': vacancies,
        })

    @http.route('/empleo/<int:vacancy_id>', type='http', auth='public', website=True, sitemap=True)
    def vacancy_form(self, vacancy_id, **kwargs):
        vacancy = request.env['venrides.vacancy'].sudo().browse(vacancy_id)
        if not vacancy.exists() or vacancy.state != 'open':
            return request.not_found()
        return request.render('venrides_recruitment.application_form', {
            'vacancy': vacancy,
            'values': {},
            'error': False,
        })

    @http.route('/empleo/<int:vacancy_id>/postular', type='http', auth='public',
                website=True, methods=['POST'], csrf=True)
    def vacancy_submit(self, vacancy_id, **kwargs):
        vacancy = request.env['venrides.vacancy'].sudo().browse(vacancy_id)
        if not vacancy.exists() or vacancy.state != 'open':
            return request.not_found()

        values = {key: value for key, value in kwargs.items()}

        def _render_error(message):
            return request.render('venrides_recruitment.application_form', {
                'vacancy': vacancy,
                'values': values,
                'error': message,
            })

        # Honeypot anti-bot
        if _clean(kwargs.get('website_url')):
            return _render_error('No se pudo procesar la postulación.')

        name = _clean(kwargs.get('partner_name'))
        national_id = _clean(kwargs.get('national_id'))
        phone = _clean(kwargs.get('partner_phone'))
        email = _clean(kwargs.get('email_from'))
        if not name or not phone:
            return _render_error('Nombre y teléfono son obligatorios.')
        if not kwargs.get('consent_privacy'):
            return _render_error(
                'Debe autorizar el tratamiento de sus datos personales para continuar.')

        applicant_vals = {
            'partner_name': name,
            'national_id': national_id,
            'partner_phone': phone,
            'email_from': email,
            'birthdate': _to_date(kwargs.get('birthdate')),
            'home_address': _clean(kwargs.get('home_address')),
            'marital_status': _clean(kwargs.get('marital_status')) or False,
            'dependents': _to_int(kwargs.get('dependents')),
            'education_level': _clean(kwargs.get('education_level')) or False,
            'availability': _to_date(kwargs.get('availability')),
            'vacancy_id': vacancy.id,
            'job_id': vacancy.job_id.id,
            'company_id': vacancy.company_id.id or request.env.company.id,
            'source_channel': _clean(kwargs.get('source_channel')) or 'web',
            'consent_privacy': True,
            'consent_date': fields.Datetime.now(),
            'form_token': secrets.token_urlsafe(16),
        }

        education = []
        for index in range(1, 4):
            institution = _clean(kwargs.get('edu_institution_%s' % index))
            if not institution:
                continue
            education.append((0, 0, {
                'institution': institution,
                'degree': _clean(kwargs.get('edu_degree_%s' % index)),
                'level': _clean(kwargs.get('edu_level_%s' % index)) or 'secondary',
                'date_start': _to_date(kwargs.get('edu_start_%s' % index)),
                'date_end': _to_date(kwargs.get('edu_end_%s' % index)),
                'current': bool(kwargs.get('edu_current_%s' % index)),
            }))
        if education:
            applicant_vals['education_ids'] = education

        experience = []
        for index in range(1, 4):
            company = _clean(kwargs.get('exp_company_%s' % index))
            if not company:
                continue
            experience.append((0, 0, {
                'company': company,
                'position': _clean(kwargs.get('exp_position_%s' % index)) or 'No indicado',
                'location': _clean(kwargs.get('exp_location_%s' % index)),
                'phone': _clean(kwargs.get('exp_phone_%s' % index)),
                'contact_name': _clean(kwargs.get('exp_contact_%s' % index)),
                'date_start': _to_date(kwargs.get('exp_start_%s' % index)),
                'date_end': _to_date(kwargs.get('exp_end_%s' % index)),
                'current': bool(kwargs.get('exp_current_%s' % index)),
                'functions': _clean(kwargs.get('exp_functions_%s' % index)),
                'reason_leave': _clean(kwargs.get('exp_reason_%s' % index)),
            }))
        if experience:
            applicant_vals['experience_ids'] = experience

        references = []
        for index in range(1, 3):
            ref_name = _clean(kwargs.get('pref_name_%s' % index))
            ref_phone = _clean(kwargs.get('pref_phone_%s' % index))
            if not ref_name or not ref_phone:
                continue
            references.append((0, 0, {
                'ref_type': 'personal',
                'name': ref_name,
                'relationship': _clean(kwargs.get('pref_relationship_%s' % index)),
                'phone': ref_phone,
                'years_known': _clean(kwargs.get('pref_years_%s' % index)),
            }))
        for index in range(1, 3):
            ref_name = _clean(kwargs.get('lref_name_%s' % index))
            ref_phone = _clean(kwargs.get('lref_phone_%s' % index))
            if not ref_name or not ref_phone:
                continue
            references.append((0, 0, {
                'ref_type': 'labor',
                'name': ref_name,
                'company': _clean(kwargs.get('lref_company_%s' % index)),
                'position': _clean(kwargs.get('lref_position_%s' % index)),
                'phone': ref_phone,
                'relationship': _clean(kwargs.get('lref_relationship_%s' % index)),
                'work_period': _clean(kwargs.get('lref_period_%s' % index)),
            }))
        if references:
            applicant_vals['reference_ids'] = references

        applicant = request.env['hr.applicant'].sudo().create(applicant_vals)

        # El enlace del test se emite al recibir la postulación.
        if vacancy.test_template_id:
            request.env['venrides.test.invitation'].sudo().create({
                'applicant_id': applicant.id,
                'template_id': vacancy.test_template_id.id,
                'channel': 'whatsapp' if applicant.source_channel == 'whatsapp' else 'email',
            })

        # Currículum adjunto (opcional)
        uploaded = request.httprequest.files.get('cv')
        if uploaded and uploaded.filename:
            data = uploaded.read()
            if len(data) <= MAX_CV_SIZE and uploaded.filename.lower().endswith('.pdf'):
                attachment = request.env['ir.attachment'].sudo().create({
                    'name': uploaded.filename,
                    'res_model': 'hr.applicant',
                    'res_id': applicant.id,
                    'raw': base64.b64encode(data).decode(),
                    'mimetype': 'application/pdf',
                })
                request.env['venrides.employee.document'].sudo().create({
                    'name': uploaded.filename,
                    'doc_type': 'cv',
                    'applicant_id': applicant.id,
                    'attachment_id': attachment.id,
                    'company_id': applicant.company_id.id,
                })

        return request.redirect('/postulacion/%s' % applicant.form_token)

    @http.route('/postulacion/<string:token>', type='http', auth='public', website=True)
    def application_status(self, token, **kwargs):
        applicant = request.env['hr.applicant'].sudo().search(
            [('form_token', '=', token)], limit=1)
        if not applicant:
            return request.not_found()
        invitation = applicant.test_invitation_ids.sorted('id', reverse=True)[:1]
        return request.render('venrides_recruitment.application_status', {
            'applicant': applicant,
            'invitation': invitation,
        })

    # ------------------------------------------------------------------
    # Test público
    # ------------------------------------------------------------------
    @http.route('/test/<string:token>', type='http', auth='public', website=True)
    def test_form(self, token, **kwargs):
        invitation = request.env['venrides.test.invitation'].sudo().search(
            [('token', '=', token)], limit=1)
        if not invitation:
            return request.not_found()

        today = fields.Date.context_today(invitation)
        if invitation.state == 'done':
            return request.render('venrides_recruitment.test_done', {
                'invitation': invitation,
                'already_done': True,
            })
        if invitation.state in ('expired', 'cancelled') or (
                invitation.expiry_date and invitation.expiry_date < today):
            if invitation.state not in ('expired', 'cancelled'):
                invitation.write({'state': 'expired'})
            return request.render('venrides_recruitment.test_expired', {
                'invitation': invitation,
            })

        if invitation.state in ('draft', 'sent'):
            invitation.write({
                'state': 'opened',
                'opened_date': fields.Datetime.now(),
            })
        return request.render('venrides_recruitment.test_form', {
            'invitation': invitation,
            'template': invitation.template_id,
            'error': False,
        })

    @http.route('/test/<string:token>/enviar', type='http', auth='public',
                website=True, methods=['POST'], csrf=True)
    def test_submit(self, token, **kwargs):
        invitation = request.env['venrides.test.invitation'].sudo().search(
            [('token', '=', token)], limit=1)
        if not invitation:
            return request.not_found()
        if invitation.state == 'done':
            return request.render('venrides_recruitment.test_done', {
                'invitation': invitation,
                'already_done': True,
            })

        template = invitation.template_id
        answers = {}
        for question in template.question_ids:
            answers[question.id] = [
                _to_int(value) for value in
                request.httprequest.form.getlist('q_%s' % question.id) if _to_int(value)
            ]

        unanswered = [
            question for question in template.question_ids
            if not answers.get(question.id)
        ]
        if unanswered:
            return request.render('venrides_recruitment.test_form', {
                'invitation': invitation,
                'template': template,
                'error': 'Debe responder todas las preguntas antes de enviar.',
            })

        lines = []
        total = 0.0
        maximum = 0.0
        for question in template.question_ids:
            selected = set(answers.get(question.id, []))
            correct = set(question.option_ids.filtered('is_correct').ids)
            is_correct = bool(correct) and selected == correct
            score = question.weight if is_correct else 0.0
            total += score
            maximum += question.weight
            lines.append((0, 0, {
                'question_id': question.id,
                'selected_option_ids': [(6, 0, list(selected))],
                'is_correct': is_correct,
                'score': score,
                'max_score': question.weight,
            }))

        attempt = request.env['venrides.test.attempt'].sudo().create({
            'invitation_id': invitation.id,
            'date_start': fields.Datetime.now(),
            'date_end': fields.Datetime.now(),
            'state': 'done',
            'score': total,
            'max_score': maximum,
            'line_ids': lines,
            'ip_address': request.httprequest.remote_addr,
            'user_agent': (request.httprequest.user_agent.string or '')[:250],
            'company_id': invitation.company_id.id,
        })

        invitation.write({
            'state': 'done',
            'submitted_date': fields.Datetime.now(),
        })

        # Registro en la hoja de vida: fase de test (no limitativa).
        percentage = (total / maximum * 100.0) if maximum else 0.0
        result = 'passed' if percentage >= template.pass_score else 'pending'
        request.env['venrides.selection.phase'].sudo().create({
            'applicant_id': invitation.applicant_id.id,
            'phase_type': 'test',
            'date': fields.Date.context_today(invitation),
            'result': result,
            'score': percentage,
            'notes': 'Test %s: %s/%s puntos (%.1f %%).' % (
                template.name, total, maximum, percentage),
            'company_id': invitation.company_id.id,
        })

        # Foto del postulante para el expediente (fase I).
        photo_data = kwargs.get('photo_data') or ''
        if photo_data.startswith('data:image/'):
            try:
                _header, photo_b64 = photo_data.split(',', 1)
                optimized = self._optimize_photo(base64.b64decode(photo_b64))
                applicant = invitation.applicant_id
                applicant.write({
                    'photo': base64.b64encode(optimized).decode(),
                    'photo_date': fields.Datetime.now(),
                })
                attachment = request.env['ir.attachment'].sudo().create({
                    'name': 'foto-postulante.jpg',
                    'res_model': 'hr.applicant',
                    'res_id': applicant.id,
                    'raw': base64.b64encode(optimized).decode(),
                    'mimetype': 'image/jpeg',
                })
                request.env['venrides.employee.document'].sudo().create({
                    'name': 'Foto del postulante',
                    'doc_type': 'photo',
                    'applicant_id': applicant.id,
                    'attachment_id': attachment.id,
                    'date': fields.Date.context_today(invitation),
                    'company_id': applicant.company_id.id,
                })
            except Exception:  # noqa: BLE001 - la foto es opcional
                pass

        return request.render('venrides_recruitment.test_done', {
            'invitation': invitation,
            'attempt': attempt,
            'already_done': False,
        })

    def _optimize_photo(self, data):
        image = Image.open(io.BytesIO(data)).convert('RGB')
        image.thumbnail((800, 800))
        output = io.BytesIO()
        image.save(output, format='JPEG', quality=75, optimize=True)
        return output.getvalue()
