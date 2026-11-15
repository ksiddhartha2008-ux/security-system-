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

type TriShieldFeatures = {
  enabled: boolean;
  network: boolean;
  endpoint: boolean;
  ipShield: boolean;
  response: boolean;
  apply: boolean;
  autoApply: boolean;
};

type AuthState = {
  user: User | null;
  organization: Organization | null;
  permissions: { canWrite: boolean; canAdmin: boolean; canApprove: boolean };
  features: { websiteProtection: boolean; trishield: TriShieldFeatures };
  loading: boolean;
  login: (email: string, password: string) => Promise<{ mfaRequired: boolean }>;
  register: (input: { name: string; email: string; password: string; organizationName: string }) => Promise<void>;
  logout: () => Promise<void>;
  refresh: () => Promise<void>;
};

const EMPTY_PERMISSIONS = { canWrite: false, canAdmin: false, canApprove: false };
const EMPTY_FEATURES = {
  websiteProtection: false,
  trishield: { enabled: false, network: false, endpoint: false, ipShield: false, response: false, apply: false, autoApply: false },
};

/**
 * A server from an older build may not send every feature flag. Merge the
 * response onto the defaults so a missing field can never crash the shell.
 */
function normalizeFeatures(input?: Partial<AuthState['features']>): AuthState['features'] {
  return {
    ...EMPTY_FEATURES,
    ...(input ?? {}),
    trishield: { ...EMPTY_FEATURES.trishield, ...(input?.trishield ?? {}) },
  };
}

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
      const data = await api.get<{ user: User; organization: Organization; permissions: AuthState['permissions']; features?: Partial<AuthState['features']> }>('/auth/me');
      setUser(data.user);
      setOrganization(data.organization);
      setPermissions(data.permissions);
      setFeatures(normalizeFeatures(data.features));
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
