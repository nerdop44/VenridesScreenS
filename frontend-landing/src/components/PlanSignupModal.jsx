import React, { useState } from 'react';
import FormService from '../services/FormService';

const PlanSignupModal = ({ isOpen, onClose, planName }) => {
    const [formData, setFormData] = useState({
        nombre: '',
        email: '',
        telefono: '',
        empresa: '',
        tipo_negocio: '',
        pantallas_estimadas: '',
        mensaje: ''
    });

    const [isSubmitting, setIsSubmitting] = useState(false);
    const [submitStatus, setSubmitStatus] = useState(null); // 'success' | 'error'
    const [errorMessage, setErrorMessage] = useState('');

    const handleChange = (e) => {
        setFormData({
            ...formData,
            [e.target.name]: e.target.value
        });
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setIsSubmitting(true);
        setSubmitStatus(null);
        setErrorMessage('');

        try {
            const response = await FormService.submitPlanSignup(planName, formData);
            setSubmitStatus('success');

            // Reset form after 2 seconds and close modal
            setTimeout(() => {
                setFormData({
                    nombre: '',
                    email: '',
                    telefono: '',
                    empresa: '',
                    tipo_negocio: '',
                    pantallas_estimadas: '',
                    mensaje: ''
                });
                setSubmitStatus(null);
                onClose();
            }, 2000);

        } catch (error) {
            setSubmitStatus('error');
            setErrorMessage(error.message || 'Error al enviar el formulario');
        } finally {
            setIsSubmitting(false);
        }
    };

    if (!isOpen) return null;

    return (
        <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/80 backdrop-blur-sm" onClick={onClose}>
            <div className="glass max-w-2xl w-full mx-4 p-8 rounded-3xl border border-white/20 max-h-[90vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
                {/* Header */}
                <div className="flex justify-between items-center mb-6">
                    <div>
                        <h2 className="text-3xl font-black uppercase">
                            Contratar Plan <span className="text-primary">{planName}</span>
                        </h2>
                        <p className="text-slate-400 text-sm mt-2">Completa el formulario y nos contactaremos contigo</p>
                    </div>
                    <button
                        onClick={onClose}
                        className="w-10 h-10 flex items-center justify-center rounded-full hover:bg-white/10 transition-colors"
                    >
                        <span className="material-symbols-outlined">close</span>
                    </button>
                </div>

                {/* Success Message */}
                {submitStatus === 'success' && (
                    <div className="mb-6 p-4 bg-primary/20 border border-primary rounded-xl flex items-center gap-3">
                        <span className="material-symbols-outlined text-primary">check_circle</span>
                        <p className="text-primary font-bold">¡Gracias! Hemos recibido tu solicitud. Te contactaremos pronto.</p>
                    </div>
                )}

                {/* Error Message */}
                {submitStatus === 'error' && (
                    <div className="mb-6 p-4 bg-red-500/20 border border-red-500 rounded-xl flex items-center gap-3">
                        <span className="material-symbols-outlined text-red-500">error</span>
                        <p className="text-red-500">{errorMessage}</p>
                    </div>
                )}

                {/* Form */}
                <form onSubmit={handleSubmit} className="space-y-4">
                    <div className="grid md:grid-cols-2 gap-4">
                        <div>
                            <label className="block text-sm font-mono uppercase tracking-wider mb-2">
                                Nombre Completo *
                            </label>
                            <input
                                type="text"
                                name="nombre"
                                value={formData.nombre}
                                onChange={handleChange}
                                required
                                className="w-full bg-slate-900/50 border border-white/10 rounded-xl px-4 py-3 focus:border-primary focus:outline-none transition-colors"
                                placeholder="Juan Pérez"
                            />
                        </div>

                        <div>
                            <label className="block text-sm font-mono uppercase tracking-wider mb-2">
                                Email *
                            </label>
                            <input
                                type="email"
                                name="email"
                                value={formData.email}
                                onChange={handleChange}
                                required
                                className="w-full bg-slate-900/50 border border-white/10 rounded-xl px-4 py-3 focus:border-primary focus:outline-none transition-colors"
                                placeholder="juan@empresa.com"
                            />
                        </div>
                    </div>

                    <div className="grid md:grid-cols-2 gap-4">
                        <div>
                            <label className="block text-sm font-mono uppercase tracking-wider mb-2">
                                Teléfono *
                            </label>
                            <input
                                type="tel"
                                name="telefono"
                                value={formData.telefono}
                                onChange={handleChange}
                                required
                                className="w-full bg-slate-900/50 border border-white/10 rounded-xl px-4 py-3 focus:border-primary focus:outline-none transition-colors"
                                placeholder="+58 412-1234567"
                            />
                        </div>

                        <div>
                            <label className="block text-sm font-mono uppercase tracking-wider mb-2">
                                Empresa/Negocio *
                            </label>
                            <input
                                type="text"
                                name="empresa"
                                value={formData.empresa}
                                onChange={handleChange}
                                required
                                className="w-full bg-slate-900/50 border border-white/10 rounded-xl px-4 py-3 focus:border-primary focus:outline-none transition-colors"
                                placeholder="Mi Empresa S.A."
                            />
                        </div>
                    </div>

                    <div className="grid md:grid-cols-2 gap-4">
                        <div>
                            <label className="block text-sm font-mono uppercase tracking-wider mb-2">
                                Tipo de Negocio *
                            </label>
                            <select
                                name="tipo_negocio"
                                value={formData.tipo_negocio}
                                onChange={handleChange}
                                required
                                className="w-full bg-slate-900/50 border border-white/10 rounded-xl px-4 py-3 focus:border-primary focus:outline-none transition-colors"
                            >
                                <option value="">Selecciona...</option>
                                <option value="Restaurante">Restaurante</option>
                                <option value="Retail">Retail/Tienda</option>
                                <option value="Clínica">Clínica/Salud</option>
                                <option value="Gimnasio">Gimnasio</option>
                                <option value="Hotel">Hotel</option>
                                <option value="Centro Comercial">Centro Comercial</option>
                                <option value="Oficina">Oficina Corporativa</option>
                                <option value="Otro">Otro</option>
                            </select>
                        </div>

                        <div>
                            <label className="block text-sm font-mono uppercase tracking-wider mb-2">
                                Pantallas Estimadas *
                            </label>
                            <select
                                name="pantallas_estimadas"
                                value={formData.pantallas_estimadas}
                                onChange={handleChange}
                                required
                                className="w-full bg-slate-900/50 border border-white/10 rounded-xl px-4 py-3 focus:border-primary focus:outline-none transition-colors"
                            >
                                <option value="">Selecciona...</option>
                                <option value="1-2">1-2 pantallas</option>
                                <option value="3-5">3-5 pantallas</option>
                                <option value="6-10">6-10 pantallas</option>
                                <option value="11-20">11-20 pantallas</option>
                                <option value="20+">Más de 20</option>
                            </select>
                        </div>
                    </div>

                    <div>
                        <label className="block text-sm font-mono uppercase tracking-wider mb-2">
                            Mensaje (Opcional)
                        </label>
                        <textarea
                            name="mensaje"
                            value={formData.mensaje}
                            onChange={handleChange}
                            rows="4"
                            className="w-full bg-slate-900/50 border border-white/10 rounded-xl px-4 py-3 focus:border-primary focus:outline-none transition-colors resize-none"
                            placeholder="Cuéntanos más sobre tu proyecto..."
                        />
                    </div>

                    {/* Submit Button */}
                    <div className="flex gap-4 pt-4">
                        <button
                            type="button"
                            onClick={onClose}
                            className="flex-1 py-3 rounded-xl border border-white/20 font-bold hover:bg-white/5 transition-colors uppercase"
                        >
                            Cancelar
                        </button>
                        <button
                            type="submit"
                            disabled={isSubmitting}
                            className="flex-1 py-3 rounded-xl bg-primary text-black font-bold hover:brightness-110 transition-all uppercase disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                            {isSubmitting ? 'Enviando...' : 'Enviar Solicitud'}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
};

export default PlanSignupModal;
