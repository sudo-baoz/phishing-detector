import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import LanguageDetector from 'i18next-browser-languagedetector';

// Import translation files
import en from './locales/en.json';
import vi from './locales/vi.json';

i18n
    .use(LanguageDetector) // Detect user language
    .use(initReactI18next) // Pass i18n to react-i18next
    .init({
        resources: {
            en: { translation: en },
            vi: { translation: vi }
        },
        fallbackLng: 'en', // Fallback language
        lng: 'en', // Default language

        interpolation: {
            escapeValue: false // React already escapes values
        },

        detection: {
            order: ['localStorage', 'navigator'],
            caches: ['localStorage']
        }
    });

export default i18n;
