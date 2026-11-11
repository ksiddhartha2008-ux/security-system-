import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { api, ApiError } from './api';

export type Role = 'admin' | 'analyst' | 'viewer';

export type User = {
  id: string;
  email: string;
  name: string;
  role: Role;
  orgId: string;
  orgName: string | null;
  mfaEnabled?: boolean;
};

export type Organization = {
  id: string;
  name: string;
  slug: string;
  plan: string;
  settings: Record<string, unknown>;
};

type AuthState = {
  user: User | null;
  organization: Organization | null;
  permissions: { canWrite: boolean; canAdmin: boolean; canApprove: boolean };
  features: { websiteProtection: boolean };
  loading: boolean;
  login: (email: string, password: string) => Promise<{ mfaRequired: boolean }>;
  register: (input: { name: string; email: string; password: string; organizationName: string }) => Promise<void>;
  logout: () => Promise<void>;
  refresh: () => Promise<void>;
};

const EMPTY_PERMISSIONS = { canWrite: false, canAdmin: false, canApprove: false };
const EMPTY_FEATURES = { websiteProtection: false };

const AuthContext = createContext<AuthState>({
  user: null,
  organization: null,
  permissions: EMPTY_PERMISSIONS,
  features: EMPTY_FEATURES,
  loading: true,
  login: async () => ({ mfaRequired: false }),
  register: async () => {},
  logout: async () => {},
  refresh: async () => {},
});

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [organization, setOrganization] = useState<Organization | null>(null);
  const [permissions, setPermissions] = useState(EMPTY_PERMISSIONS);
  const [features, setFeatures] = useState(EMPTY_FEATURES);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    try {
      const data = await api.get<{ user: User; organization: Organization; permissions: AuthState['permissions']; features?: AuthState['features'] }>('/auth/me');
      setUser(data.user);
      setOrganization(data.organization);
      setPermissions(data.permissions);
      setFeatures(data.features ?? EMPTY_FEATURES);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        setUser(null);
        setOrganization(null);
        setPermissions(EMPTY_PERMISSIONS);
        setFeatures(EMPTY_FEATURES);
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const login = useCallback(async (email: string, password: string) => {
    const response = await api.post<{ mfaRequired?: boolean }>('/auth/login', { email, password });
    if (response?.mfaRequired) return { mfaRequired: true };
    await load();
    return { mfaRequired: false };
  }, [load]);

  const register = useCallback(async (input: { name: string; email: string; password: string; organizationName: string }) => {
    await api.post('/auth/register', input);
    await load();
  }, [load]);

  const logout = useCallback(async () => {
    try { await api.post('/auth/logout'); } finally {
      setUser(null);
      setOrganization(null);
      setPermissions(EMPTY_PERMISSIONS);
      setFeatures(EMPTY_FEATURES);
    }
  }, []);

  const value = useMemo(() => ({ user, organization, permissions, features, loading, login, register, logout, refresh: load }),
    [user, organization, permissions, features, loading, login, register, logout, load]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export const useAuth = () => useContext(AuthContext);
