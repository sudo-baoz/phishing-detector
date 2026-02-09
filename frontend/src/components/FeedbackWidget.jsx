/**
 * Phishing Detector - Community Feedback Loop (False Positive / False Negative)
 * Copyright (c) 2026 BaoZ
 *
 * Dark-mode widget: "Result incorrect? Report to AI." → modal form → submit → thanks.
 * No PII collected (no email, name, IP).
 */

import { useState } from 'react';
import { MessageCircle, CheckCircle, XCircle, Lock } from 'lucide-react';
import { submitFeedback } from '../services/api';

const FeedbackWidget = ({ url, predictedVerdict }) => {
  const [open, setOpen] = useState(false);
  const [userCorrection, setUserCorrection] = useState(null);
  const [reason, setReason] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [error, setError] = useState(null);

  const handleSubmit = async () => {
    if (!userCorrection || !url || !predictedVerdict) return;
    setError(null);
    setSubmitting(true);
    try {
      await submitFeedback({
        url,
        predicted_verdict: predictedVerdict,
        user_correction: userCorrection,
        reason: reason.trim() || undefined,
      });
      setSubmitted(true);
      setTimeout(() => {
        setOpen(false);
        setSubmitted(false);
        setUserCorrection(null);
        setReason('');
      }, 2500);
    } catch (e) {
      setError(e.response?.data?.detail || e.message || 'Failed to send. Try again.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleClose = () => {
    if (submitted) return;
    setOpen(false);
    setUserCorrection(null);
    setReason('');
    setError(null);
  };

  return (
    <div className="mt-6">
      <button
        type="button"
        onClick={() => setOpen(true)}
        className="inline-flex items-center gap-2 text-slate-400 hover:text-cyan-400 text-sm transition-colors"
      >
        <MessageCircle className="w-4 h-4" />
        Result incorrect? Report to AI.
      </button>

      {open && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-700 rounded-xl shadow-2xl w-full max-w-md overflow-hidden">
            <div className="p-5 sm:p-6">
              {!submitted ? (
                <>
                  <h3 className="text-lg font-bold text-slate-100 mb-4">
                    Help Improve Accuracy
                  </h3>
                  <p className="text-slate-400 text-sm mb-4">
                    Our AI said: <span className={predictedVerdict === 'PHISHING' ? 'text-red-400' : 'text-green-400'}>{predictedVerdict}</span>. What do you think?
                  </p>
                  <div className="flex gap-3 mb-4">
                    <button
                      type="button"
                      onClick={() => setUserCorrection('SAFE')}
                      className={`flex-1 flex items-center justify-center gap-2 py-3 px-4 rounded-lg border-2 font-semibold transition-all ${
                        userCorrection === 'SAFE'
                          ? 'border-green-500 bg-green-500/20 text-green-400'
                          : 'border-slate-600 text-slate-400 hover:border-green-500/50 hover:text-green-400'
                      }`}
                    >
                      <CheckCircle className="w-5 h-5" />
                      It's actually SAFE
                    </button>
                    <button
                      type="button"
                      onClick={() => setUserCorrection('PHISHING')}
                      className={`flex-1 flex items-center justify-center gap-2 py-3 px-4 rounded-lg border-2 font-semibold transition-all ${
                        userCorrection === 'PHISHING'
                          ? 'border-red-500 bg-red-500/20 text-red-400'
                          : 'border-slate-600 text-slate-400 hover:border-red-500/50 hover:text-red-400'
                      }`}
                    >
                      <XCircle className="w-5 h-5" />
                      It's actually PHISHING
                    </button>
                  </div>
                  <label className="block text-slate-400 text-sm mb-1">Why? (optional)</label>
                  <input
                    type="text"
                    value={reason}
                    onChange={(e) => setReason(e.target.value.slice(0, 200))}
                    placeholder="e.g., Official domain, Broken layout..."
                    className="w-full px-3 py-2 bg-slate-800 border border-slate-600 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/50 focus:border-cyan-500"
                    maxLength={200}
                  />
                  <p className="mt-3 flex items-center gap-2 text-slate-500 text-xs">
                    <Lock className="w-3.5 h-3.5 shrink-0" />
                    We do not collect your personal info (Email/IP). Data is used solely for AI training.
                  </p>
                  {error && (
                    <p className="mt-2 text-red-400 text-sm">{error}</p>
                  )}
                </>
              ) : (
                <div className="py-4 text-center">
                  <CheckCircle className="w-12 h-12 text-green-500 mx-auto mb-2" />
                  <p className="text-slate-200 font-medium">Thanks! Our AI will learn from this.</p>
                </div>
              )}
            </div>
            {!submitted && (
              <div className="px-5 sm:px-6 pb-5 flex gap-3">
                <button
                  type="button"
                  onClick={handleClose}
                  className="flex-1 py-2.5 rounded-lg border border-slate-600 text-slate-400 hover:bg-slate-800 transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={handleSubmit}
                  disabled={!userCorrection || submitting}
                  className="flex-1 py-2.5 rounded-lg bg-cyan-600 text-white font-medium hover:bg-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  {submitting ? 'Sending…' : 'Submit'}
                </button>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default FeedbackWidget;
