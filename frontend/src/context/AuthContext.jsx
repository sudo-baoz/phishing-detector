/**
 * Auth state: user, login(email, password), logout(). JWT in localStorage.
 */

import { createContext, useContext, useState, useEffect, useCallback } from 'react';
import axios from 'axios';

const STORAGE_KEY = 'cybersentinel-token';
const API_URL = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

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
        .get(`${API_URL}/auth/me`, { headers: { Authorization: `Bearer ${t}` } })
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
    const body = new URLSearchParams({ username: email, password });
    const { data } = await axios.post(`${API_URL}/auth/token`, body, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });
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
