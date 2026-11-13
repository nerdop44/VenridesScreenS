# -*- coding: utf-8 -*-
import base64
import io
import secrets

from PIL import Image

from odoo import fields, http
from odoo.http import request

from .main import _clean, _to_date, _to_int


MAX_CV_SIZE = 5 * 1024 * 1024


class VenridesProcessController(http.Controller):

    def _get_link(self, token):
        return request.env['venrides.application.link'].sudo().search(
            [('token', '=', token)], limit=1)

    def _get_templates(self, link):
        if link.template_ids:
            return link.template_ids
        return request.env['venrides.test.template'].sudo().search([
            ('active', '=', True),
            ('area', 'in', ('atc', 'general', 'kitchen')),
        ], order='sequence, id')

    def _get_vacancies(self):
        return request.env['venrides.vacancy'].sudo().search(
            [('state', '=', 'open')], order='sequence, id')

    def _optimize_photo(self, data):
        image = Image.open(io.BytesIO(data)).convert('RGB')
        image.thumbnail((800, 800))
        output = io.BytesIO()
        image.save(output, format='JPEG', quality=75, optimize=True)
        return output.getvalue()

    def _create_applicant(self, vacancy, kwargs):
        if _clean(kwargs.get('website_url')):
            raise ValueError('No se pudo procesar la postulación.')
        name = _clean(kwargs.get('partner_name'))
        phone = _clean(kwargs.get('partner_phone'))
        if not name or not phone:
            raise ValueError('Nombre y teléfono son obligatorios.')
        if not kwargs.get('consent_privacy'):
            raise ValueError(
                'Debe autorizar el tratamiento de sus datos personales para continuar.')

        vals = {
            'partner_name': name,
            'national_id': _clean(kwargs.get('national_id')),
            'partner_phone': phone,
            'email_from': _clean(kwargs.get('email_from')),
            'birthdate': _to_date(kwargs.get('birthdate')),
            'home_address': _clean(kwargs.get('home_address')),
            'marital_status': _clean(kwargs.get('marital_status')) or False,
            'dependents': _to_int(kwargs.get('dependents')),
            'education_level': _clean(kwargs.get('education_level')) or False,
            'availability': _to_date(kwargs.get('availability')),
            'vacancy_id': vacancy.id,
            'job_id': vacancy.job_id.id,
            'company_id': vacancy.company_id.id or request.env.company.id,
            'source_channel': 'whatsapp',
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
            vals['education_ids'] = education

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
            vals['experience_ids'] = experience

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
            vals['reference_ids'] = references

        applicant = request.env['hr.applicant'].sudo().create(vals)

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

        photo_data = kwargs.get('photo_data') or ''
        if photo_data.startswith('data:image/'):
            try:
                _header, photo_b64 = photo_data.split(',', 1)
                optimized = self._optimize_photo(base64.b64decode(photo_b64))
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
                    'date': fields.Date.context_today(applicant),
                    'company_id': applicant.company_id.id,
                })
            except Exception:  # noqa: BLE001
                pass
        return applicant

    def _score(self, template, answers):
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
        return lines, total, maximum

    @http.route('/proceso/<string:token>', type='http', auth='public', website=True)
    def process_form(self, token, **kwargs):
        link = self._get_link(token)
        if not link:
            return request.not_found()
        if link.state == 'submitted':
            return request.render('venrides_recruitment.process_done', {
                'link': link, 'applicant': link.applicant_id})
        today = fields.Date.context_today(link)
        if link.state in ('expired', 'cancelled') or (link.expiry_date and link.expiry_date < today):
            if link.state not in ('expired', 'cancelled'):
                link.write({'state': 'expired'})
            return request.render('venrides_recruitment.process_expired', {'link': link})
        if link.state == 'new':
            link.write({'state': 'opened', 'opened_date': fields.Datetime.now()})
        return request.render('venrides_recruitment.process_form', {
            'link': link,
            'vacancies': self._get_vacancies(),
            'templates': self._get_templates(link),
            'values': {},
            'answers': {},
            'error': False,
        })

    @http.route('/proceso/<string:token>/enviar', type='http', auth='public',
                website=True, methods=['POST'], csrf=True)
    def process_submit(self, token, **kwargs):
        link = self._get_link(token)
        if not link:
            return request.not_found()
        if link.state == 'submitted':
            return request.render('venrides_recruitment.process_done', {
                'link': link, 'applicant': link.applicant_id})
        today = fields.Date.context_today(link)
        if link.state in ('expired', 'cancelled') or (link.expiry_date and link.expiry_date < today):
            if link.state not in ('expired', 'cancelled'):
                link.write({'state': 'expired'})
            return request.render('venrides_recruitment.process_expired', {'link': link})

        values = {key: value for key, value in kwargs.items()}
        templates = self._get_templates(link)
        if not templates:
            return request.render('venrides_recruitment.process_form', {
                'link': link, 'vacancies': self._get_vacancies(), 'templates': templates,
                'values': values, 'answers': {}, 'error': 'No hay tests configurados.'})

        vacancy = link.vacancy_id
        if not vacancy:
            vacancy_id = _to_int(kwargs.get('vacancy_id'))
            vacancy = request.env['venrides.vacancy'].sudo().browse(vacancy_id)
            if not vacancy.exists() or vacancy.state != 'open':
                return request.render('venrides_recruitment.process_form', {
                    'link': link, 'vacancies': self._get_vacancies(), 'templates': templates,
                    'values': values, 'answers': {}, 'error': 'Selecciona el puesto al que postulas.'})

        answers = {}
        missing = []
        for template in templates:
            for question in template.question_ids:
                selected = [
                    _to_int(value) for value in
                    request.httprequest.form.getlist('q_%s' % question.id) if _to_int(value)]
                answers[question.id] = selected
                if not selected:
                    missing.append(question.name)
        if missing:
            return request.render('venrides_recruitment.process_form', {
                'link': link, 'vacancies': self._get_vacancies(), 'templates': templates,
                'values': values, 'answers': answers,
                'error': 'Faltan %s preguntas por responder.' % len(missing)})

        try:
            applicant = self._create_applicant(vacancy, kwargs)
        except ValueError as exc:
            return request.render('venrides_recruitment.process_form', {
                'link': link, 'vacancies': self._get_vacancies(), 'templates': templates,
                'values': values, 'answers': answers, 'error': str(exc)})

        now = fields.Datetime.now()
        for template in templates:
            lines, total, maximum = self._score(template, answers)
            invitation = request.env['venrides.test.invitation'].sudo().create({
                'applicant_id': applicant.id,
                'template_id': template.id,
                'state': 'done',
                'channel': 'whatsapp',
                'sent_date': now,
                'opened_date': now,
                'submitted_date': now,
            })
            request.env['venrides.test.attempt'].sudo().create({
                'invitation_id': invitation.id,
                'date_start': now,
                'date_end': now,
                'state': 'done',
                'score': total,
                'max_score': maximum,
                'line_ids': lines,
                'ip_address': request.httprequest.remote_addr,
                'user_agent': (request.httprequest.user_agent.string or '')[:250],
                'company_id': applicant.company_id.id,
            })
            percentage = (total / maximum * 100.0) if maximum else 0.0
            result = 'passed' if percentage >= template.pass_score else 'pending'
            request.env['venrides.selection.phase'].sudo().create({
                'applicant_id': applicant.id,
                'phase_type': 'test',
                'date': fields.Date.context_today(link),
                'result': result,
                'score': percentage,
                'notes': 'Test %s: %s/%s puntos (%.1f %%).' % (
                    template.name, total, maximum, percentage),
                'company_id': applicant.company_id.id,
            })

        link.write({
            'state': 'submitted',
            'applicant_id': applicant.id,
            'submitted_date': now,
        })
        return request.render('venrides_recruitment.process_done', {
            'link': link, 'applicant': applicant})
