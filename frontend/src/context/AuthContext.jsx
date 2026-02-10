/**
 * Auth state: user, login(email, password), logout(). JWT in localStorage.
 */

import { createContext, useContext, useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { getApiUrl } from '../constants/api';

const STORAGE_KEY = 'cybersentinel-token';

const AuthContext = createContext({
  user: null,
  token: null,
  login: async () => {},
  logout: () => {},
  loading: true,
});

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(null);
  const [loading, setLoading] = useState(true);

  const loadStored = useCallback(() => {
    try {
      const t = localStorage.getItem(STORAGE_KEY);
      if (!t) {
        setToken(null);
        setUser(null);
        setLoading(false);
        return;
      }
      setToken(t);
      axios
        .get(getApiUrl('auth/me'), { headers: { Authorization: `Bearer ${t}` } })
        .then((r) => {
          setUser(r.data);
          setLoading(false);
        })
        .catch(() => {
          localStorage.removeItem(STORAGE_KEY);
          setToken(null);
          setUser(null);
          setLoading(false);
        });
    } catch {
      setToken(null);
      setUser(null);
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadStored();
  }, [loadStored]);

  const login = useCallback(async (email, password) => {
    // CRITICAL: OAuth2 /auth/token expects form-urlencoded with "username" and "password".
    // Do NOT send JSON. Use fetch + URLSearchParams so the server receives form data.
    const body = new URLSearchParams();
    body.append('username', email);
    body.append('password', password);

    const res = await fetch(getApiUrl('auth/token'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });

    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
      const message = Array.isArray(data.detail)
        ? data.detail.map((x) => x?.msg || x).join(', ')
        : (data.detail || data.message || `Request failed (${res.status})`);
      const err = new Error(message);
      err.status = res.status;
      err.response = { data };
      throw err;
    }

    const t = data.access_token;
    localStorage.setItem(STORAGE_KEY, t);
    setToken(t);
    setUser(data.user || { id: data.sub, email });
    return data;
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem(STORAGE_KEY);
    setToken(null);
    setUser(null);
  }, []);

  return (
    <AuthContext.Provider value={{ user, token, login, logout, loading }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
