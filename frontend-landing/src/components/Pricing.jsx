import React, { useState } from 'react';
import PlanSignupModal from './PlanSignupModal';

const Pricing = ({ onOpenContact }) => {
    const [isAnnual, setIsAnnual] = useState(false);
    const [selectedPlan, setSelectedPlan] = useState(null);
    const [isModalOpen, setIsModalOpen] = useState(false);

    const handlePlanSelect = (planId) => {
        setSelectedPlan(planId);
        setIsModalOpen(true);
    };

    const plans = [
        {
            id: 'free',
            name: 'Free',
            subtitle: 'Starter',
            monthlyPrice: 0,
            annualPrice: 0,
            screens: '2 pantallas',
            features: [
                'Hasta 2 pantallas',
                'Contenido publicitario básico',
                'Programación de publicidad',
                'Panel web completo',
                'Publicidad de terceros',
                'Soporte Helpdesk'
            ]
        },
        {
            id: 'basic',
            name: 'Emprendedor',
            subtitle: 'Básico',
            monthlyPrice: 30,
            annualPrice: 320,
            screens: '5 pantallas',
            features: [
                'Hasta 5 pantallas',
                'Contenido publicitario',
                'Sin publicidad de terceros',
                'Programación avanzada',
                'Panel web completo',
                'Multi-ubicación',
                'Soporte Helpdesk'
            ]
        },
        {
            id: 'plus',
            name: 'Profesional',
            subtitle: 'Plus',
            monthlyPrice: 50,
            annualPrice: 520,
            screens: '10 pantallas',
            popular: true,
            features: [
                'Hasta 10 pantallas',
                'Contenido publicitario',
                'Sin publicidad de terceros',
                'Panel web y app móvil completo',
                'Multi-ubicación',
                'Capacitación personalizada',
                'Soporte dedicado'
            ]
        },
        {
            id: 'ultra',
            name: 'Enterprise',
            subtitle: 'Ultra',
            monthlyPrice: 80,
            annualPrice: 850,
            screens: '20 pantallas',
            features: [
                'Hasta 20 pantallas',
                'Contenido publicitario',
                'Sin publicidad de terceros',
                'Panel web y app móvil completo',
                'Multi-ubicación',
                'Capacitación personalizada',
                'Soporte dedicado'
            ]
        },
        {
            id: 'empresarial',
            name: 'Pantallas Gigantes',
            subtitle: 'Empresarial',
            monthlyPrice: null,
            annualPrice: null,
            screens: 'Ilimitadas',
            features: [
                'Pantallas de exterior a gran formato',
                'Pantallas LED gigantes',
                'Instalación on-premise',
                'Multi-ubicación',
                'Capacitación personalizada',
                'Soporte dedicado'
            ]
        }
    ];

    return (
        <section className="py-32 bg-slate-900/50" id="precios">
            <div className="max-w-7xl mx-auto px-6 text-center mb-12">
                <h2 className="text-5xl md:text-7xl font-black uppercase mb-6 italic leading-none">
                    Planes <span className="text-primary">Estratégicos</span>
                </h2>
                <p className="text-slate-400 font-mono text-sm tracking-widest uppercase mb-8">
                    Escalabilidad pura para tu negocio digital
                </p>

                {/* Toggle Mensual/Anual */}
                <div className="flex items-center justify-center gap-4 mb-12">
                    <span className={`font-mono text-sm uppercase tracking-wider transition-colors ${!isAnnual ? 'text-primary font-bold' : 'text-slate-500'}`}>
                        Mensual
                    </span>
                    <button
                        onClick={() => setIsAnnual(!isAnnual)}
                        className="relative w-16 h-8 bg-slate-700 rounded-full transition-colors hover:bg-slate-600"
                    >
                        <div className={`absolute top-1 left-1 w-6 h-6 bg-primary rounded-full transition-transform ${isAnnual ? 'translate-x-8' : ''}`}></div>
                    </button>
                    <span className={`font-mono text-sm uppercase tracking-wider transition-colors ${isAnnual ? 'text-primary font-bold' : 'text-slate-500'}`}>
                        Anual
                        <span className="ml-2 text-xs bg-primary/20 text-primary px-2 py-1 rounded-full">Ahorra hasta 17%</span>
                    </span>
                </div>
            </div>

            <div className="max-w-7xl mx-auto px-6 grid md:grid-cols-5 gap-6">
                {plans.map((plan) => (
                    <div
                        key={plan.id}
                        className={`glass p-6 rounded-3xl flex flex-col transition-all ${plan.popular
                            ? 'neon-border pulse-neon scale-105 relative z-10 bg-black/40'
                            : 'border border-white/10 hover:border-white/20'
                            }`}
                    >
                        {plan.popular && (
                            <div className="absolute -top-3 left-1/2 -translate-x-1/2 bg-primary text-black font-black text-[9px] tracking-[0.2em] px-3 py-1 rounded-full uppercase">
                                MAS POPULAR
                            </div>
                        )}

                        <span className="font-mono text-primary text-xs tracking-widest uppercase mb-3">
                            {plan.subtitle}
                        </span>
                        <h3 className="text-xl font-bold mb-2">{plan.name}</h3>

                        <div className="flex items-baseline gap-1 mb-6">
                            {plan.monthlyPrice === null ? (
                                <span className="text-2xl font-black">Personalizado</span>
                            ) : (
                                <>
                                    <span className={`text-3xl font-black ${plan.popular ? 'text-primary' : ''}`}>
                                        ${isAnnual ? plan.annualPrice : plan.monthlyPrice}
                                    </span>
                                    <span className="text-slate-500 text-sm font-mono uppercase">
                                        /{isAnnual ? 'año' : 'mes'}
                                    </span>
                                </>
                            )}
                        </div>

                        <p className="text-slate-400 text-xs mb-4 font-mono">{plan.screens}</p>

                        <ul className="space-y-3 mb-8 text-left flex-grow font-light text-slate-300 text-sm">
                            {plan.features.map((feature, idx) => (
                                <li key={idx} className="flex items-center gap-2">
                                    <span className={`material-symbols-outlined text-sm ${plan.popular ? 'text-primary' : 'text-primary'}`}>
                                        {plan.popular ? 'check_circle' : 'check'}
                                    </span>
                                    {feature}
                                </li>
                            ))}
                        </ul>

                        <button
                            onClick={() => plan.id === 'empresarial' ? onOpenContact() : handlePlanSelect(plan.id)}
                            className={`w-full py-3 rounded-xl font-bold transition-all uppercase text-sm ${plan.popular
                                ? 'bg-primary text-black hover:brightness-110'
                                : plan.id === 'empresarial'
                                    ? 'border-2 border-primary text-primary hover:bg-primary hover:text-black'
                                    : 'border border-white/20 hover:bg-white/5'
                                }`}
                        >
                            {plan.id === 'free' ? 'Comenzar' : plan.id === 'empresarial' ? 'Contactar Ventas' : 'Seleccionar'}
                        </button>
                    </div>
                ))}
            </div>

            {/* Plan Signup Modal */}
            <PlanSignupModal
                isOpen={isModalOpen}
                onClose={() => setIsModalOpen(false)}
                planName={selectedPlan || ''}
            />
        </section>
    );
};

export default Pricing;
