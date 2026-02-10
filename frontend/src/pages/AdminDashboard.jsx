/**
 * Admin Dashboard: stats cards, scans per day chart (Recharts), API key copy.
 */

import { useState, useEffect } from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { useTheme } from '../context/ThemeContext';
import { Shield, AlertTriangle, Users, Copy, Check } from 'lucide-react';
import { getApiUrl } from '../constants/api';
const DUMMY_API_KEY = 'sk-live-59' + 'a1b2c3d4e5f6';

export default function AdminDashboard() {
  const { user, token } = useAuth();
  const { theme } = useTheme();
  const [stats, setStats] = useState(null);
  const [copied, setCopied] = useState(false);
  const isDark = theme === 'dark';

  useEffect(() => {
    if (!token) return;
    axios
      .get(getApiUrl('admin/stats'), { headers: { Authorization: `Bearer ${token}` } })
      .then((r) => setStats(r.data))
      .catch(() => setStats({ total_scans: 0, phishing_detected: 0, safe_count: 0, scans_per_day: [], active_users: 0 }));
  }, [token]);

  const copyKey = () => {
    navigator.clipboard.writeText(DUMMY_API_KEY);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (!user || user.role !== 'admin') {
    return (
      <div className={isDark ? 'min-h-screen bg-black flex items-center justify-center text-slate-300' : 'min-h-screen bg-gray-50 flex items-center justify-center text-gray-700'}>
        <p>Admin access required.</p>
      </div>
    );
  }

  const s = stats || {};
  const chartData = (s.scans_per_day || []).map((d) => ({ date: d.date, count: d.count }));

  return (
    <div className={isDark ? 'min-h-screen bg-black text-slate-200' : 'min-h-screen bg-gray-50 text-gray-900'}>
      <div className="max-w-5xl mx-auto px-4 py-8">
        <h1 className="text-2xl font-bold mb-6">Admin Dashboard</h1>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-8">
          <div className={`rounded-xl border p-5 ${isDark ? 'bg-gray-900/50 border-gray-700' : 'bg-white border-gray-200'}`}>
            <div className="flex items-center gap-2 text-slate-400 mb-1">
              <Shield className="w-4 h-4" />
              Total Scans
            </div>
            <p className="text-2xl font-bold">{s.total_scans ?? 0}</p>
          </div>
          <div className={`rounded-xl border p-5 ${isDark ? 'bg-gray-900/50 border-gray-700' : 'bg-white border-gray-200'}`}>
            <div className="flex items-center gap-2 text-slate-400 mb-1">
              <AlertTriangle className="w-4 h-4" />
              Phishing Detected
            </div>
            <p className="text-2xl font-bold text-red-400">{s.phishing_detected ?? 0}</p>
          </div>
          <div className={`rounded-xl border p-5 ${isDark ? 'bg-gray-900/50 border-gray-700' : 'bg-white border-gray-200'}`}>
            <div className="flex items-center gap-2 text-slate-400 mb-1">
              <Users className="w-4 h-4" />
              Active Users
            </div>
            <p className="text-2xl font-bold">{s.active_users ?? 0}</p>
          </div>
        </div>

        <div className={`rounded-xl border p-5 mb-8 ${isDark ? 'bg-gray-900/50 border-gray-700' : 'bg-white border-gray-200'}`}>
          <h2 className="font-semibold mb-4">Scans over last 7 days</h2>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData}>
                <XAxis dataKey="date" stroke={isDark ? '#94a3b8' : '#64748b'} />
                <YAxis stroke={isDark ? '#94a3b8' : '#64748b'} />
                <Tooltip contentStyle={isDark ? { background: '#1e293b', border: '1px solid #334155' } : {}} />
                <Bar dataKey="count" fill="#22d3ee" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className={`rounded-xl border p-5 ${isDark ? 'bg-gray-900/50 border-gray-700' : 'bg-white border-gray-200'}`}>
          <h2 className="font-semibold mb-2">API Key</h2>
          <p className="text-sm text-slate-500 mb-2">Use this key for API requests (demo: dummy key).</p>
          <div className="flex items-center gap-2">
            <code className={`flex-1 px-3 py-2 rounded-lg text-sm ${isDark ? 'bg-gray-800' : 'bg-gray-100'}`}>
              {DUMMY_API_KEY}
            </code>
            <button
              type="button"
              onClick={copyKey}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm"
            >
              {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
              {copied ? 'Copied' : 'Copy'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
