/**
 * Login Modal – Portal-rendered, fixed overlay, centered card with entry animation.
 * Renders at document.body to avoid parent positioning/overflow issues.
 */

import { useState, useEffect } from 'react';
import { createPortal } from 'react-dom';

export default function LoginModal({ open, onClose, onLogin, error = '' }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [localError, setLocalError] = useState('');

  useEffect(() => {
    if (!open) return;
    setLocalError(error);
  }, [open, error]);

  useEffect(() => {
    if (!open) return;
    const handleEscape = (e) => e.key === 'Escape' && onClose();
    document.addEventListener('keydown', handleEscape);
    document.body.style.overflow = 'hidden';
    return () => {
      document.removeEventListener('keydown', handleEscape);
      document.body.style.overflow = '';
    };
  }, [open, onClose]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLocalError('');
    setSubmitting(true);
    try {
      await onLogin(email, password);
      onClose();
      setEmail('');
      setPassword('');
    } catch (err) {
      const msg = err.response?.data?.detail ?? err.message ?? 'Login failed';
      setLocalError(Array.isArray(msg) ? msg.map((x) => x?.msg ?? x).join(', ') : msg);
    } finally {
      setSubmitting(false);
    }
  };

  if (!open) return null;

  const modal = (
    <div
      className="fixed inset-0 z-[9999] flex items-center justify-center bg-black/60 backdrop-blur-sm p-4"
      onClick={onClose}
      aria-modal="true"
      role="dialog"
      aria-labelledby="login-modal-title"
    >
      <div
        className="w-full max-w-md bg-white dark:bg-gray-900 rounded-2xl shadow-2xl border border-gray-100 dark:border-gray-700 overflow-hidden relative animate-login-modal-in"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="p-6">
          <h2 id="login-modal-title" className="text-lg font-bold text-gray-900 dark:text-white mb-4">
            Login
          </h2>
          <form onSubmit={handleSubmit} className="space-y-4">
            <input
              type="email"
              placeholder="Email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              className="w-full px-4 py-2.5 rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 placeholder-gray-500 dark:placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyan-500/50 focus:border-cyan-500 transition-colors"
            />
            <input
              type="password"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              className="w-full px-4 py-2.5 rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 placeholder-gray-500 dark:placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyan-500/50 focus:border-cyan-500 transition-colors"
            />
            {localError && <p className="text-sm text-red-500 dark:text-red-400">{localError}</p>}
            <button
              type="submit"
              disabled={submitting}
              className="w-full py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {submitting ? 'Signing in…' : 'Sign in'}
            </button>
          </form>
          <p className="mt-3 text-xs text-gray-500 dark:text-gray-400">
            Demo: admin@cybersentinel.com / password123
          </p>
        </div>
      </div>
    </div>
  );

  return createPortal(modal, document.body);
}
