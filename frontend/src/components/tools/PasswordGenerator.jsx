/**
 * Security Suite - Password Generator (client-side only)
 * Length 8–32, options: uppercase, numbers, symbols. Strength meter + Copy.
 */

import { useState, useCallback } from 'react';
import { Copy, Check } from 'lucide-react';

const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const LOWER = 'abcdefghijklmnopqrstuvwxyz';
const NUM = '0123456789';
const SYMB = '!@#$%^&*()_+-=[]{}|;:,.<>?';

function generatePassword(len, opts) {
  let pool = LOWER;
  if (opts.uppercase) pool += UPPER;
  if (opts.numbers) pool += NUM;
  if (opts.symbols) pool += SYMB;
  const arr = Array.from({ length: len }, () => pool[Math.floor(Math.random() * pool.length)]);
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr.join('');
}

function getStrength(pwd) {
  if (!pwd.length) return 0;
  let s = 0;
  if (pwd.length >= 8) s += 1;
  if (pwd.length >= 12) s += 1;
  if (pwd.length >= 16) s += 1;
  if (/[A-Z]/.test(pwd)) s += 1;
  if (/[0-9]/.test(pwd)) s += 1;
  if (/[^A-Za-z0-9]/.test(pwd)) s += 1;
  return Math.min(6, s);
}

export default function PasswordGenerator() {
  const [length, setLength] = useState(16);
  const [uppercase, setUppercase] = useState(true);
  const [numbers, setNumbers] = useState(true);
  const [symbols, setSymbols] = useState(true);
  const [password, setPassword] = useState('');
  const [copied, setCopied] = useState(false);

  const generate = useCallback(() => {
    setPassword(generatePassword(length, { uppercase, numbers, symbols }));
    setCopied(false);
  }, [length, uppercase, numbers, symbols]);

  const copy = useCallback(() => {
    if (!password) return;
    navigator.clipboard.writeText(password).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }, [password]);

  const strength = getStrength(password);
  const strengthColor = strength <= 2 ? 'bg-red-500' : strength <= 4 ? 'bg-amber-500' : 'bg-green-500';

  return (
    <div className="w-full bg-transparent">
      <p className="text-slate-400 text-sm mb-4">Generate a strong password (client-side only).</p>

      <div className="space-y-4">
        <div>
          <label className="text-slate-400 text-sm block mb-1">Length: {length}</label>
          <input
            type="range"
            min={8}
            max={32}
            value={length}
            onChange={(e) => setLength(Number(e.target.value))}
            className="w-full h-2 rounded-lg appearance-none bg-slate-700 accent-cyan-500"
          />
        </div>
        <div className="flex flex-wrap gap-4">
          <label className="flex items-center gap-2 text-slate-300 cursor-pointer">
            <input type="checkbox" checked={uppercase} onChange={(e) => setUppercase(e.target.checked)} className="rounded accent-cyan-500" />
            Uppercase (A–Z)
          </label>
          <label className="flex items-center gap-2 text-slate-300 cursor-pointer">
            <input type="checkbox" checked={numbers} onChange={(e) => setNumbers(e.target.checked)} className="rounded accent-cyan-500" />
            Numbers (0–9)
          </label>
          <label className="flex items-center gap-2 text-slate-300 cursor-pointer">
            <input type="checkbox" checked={symbols} onChange={(e) => setSymbols(e.target.checked)} className="rounded accent-cyan-500" />
            Symbols (!@#)
          </label>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={generate}
            className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium"
          >
            Generate
          </button>
          <button
            type="button"
            onClick={copy}
            disabled={!password}
            className="px-4 py-2 rounded-lg bg-slate-700 hover:bg-slate-600 disabled:opacity-50 text-white font-medium flex items-center gap-2"
          >
            {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
            {copied ? 'Copied' : 'Copy'}
          </button>
        </div>
        {password && (
          <>
            <div className="rounded-lg bg-slate-800 px-3 py-2 font-mono text-sm text-slate-200 break-all">
              {password}
            </div>
            <div>
              <span className="text-slate-400 text-xs block mb-1">Strength</span>
              <div className="h-2 rounded-full bg-slate-700 overflow-hidden flex">
                {[1, 2, 3, 4, 5, 6].map((i) => (
                  <div
                    key={i}
                    className={`flex-1 transition-colors ${i <= strength ? strengthColor : 'bg-slate-700'}`}
                  />
                ))}
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
