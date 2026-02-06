/**
 * Form Service for VenridesScreenS
 * Handles form submissions to backend API
 */

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

class FormService {
    /**
     * Submit plan signup form
     * @param {string} plan - Plan name (Free, Basico, Plus, Ultra, Empresarial)
     * @param {Object} data - Form data
     * @returns {Promise<Object>} Response from server
     */
    async submitPlanSignup(plan, data) {
        try {
            const response = await fetch(`${API_BASE_URL}/api/forms/signup/plan`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    plan,
                    ...data
                })
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.detail || 'Error al enviar el formulario');
            }

            return await response.json();
        } catch (error) {
            console.error('Error submitting plan signup:', error);
            throw error;
        }
    }

    /**
     * Submit contact form
     * @param {Object} data - Form data
     * @returns {Promise<Object>} Response from server
     */
    async submitContact(data) {
        try {
            const response = await fetch(`${API_BASE_URL}/api/forms/contact`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(data)
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.detail || 'Error al enviar el formulario');
            }

            return await response.json();
        } catch (error) {
            console.error('Error submitting contact form:', error);
            throw error;
        }
    }
}

export default new FormService();
