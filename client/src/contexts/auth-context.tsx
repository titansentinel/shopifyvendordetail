import { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { getSessionFromUrl, hasValidSession } from '@/lib/session';

interface AuthContextType {
  shopDomain: string | null;
  sessionId: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (shop: string) => void;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

interface AuthProviderProps {
  children: ReactNode;
}

export function AuthProvider({ children }: AuthProviderProps) {
  const [shopDomain, setShopDomain] = useState<string | null>(null);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    // Get authentication info from URL parameters
    const { shop, session } = getSessionFromUrl();
    
    if (shop && session) {
      setShopDomain(shop);
      setSessionId(session);
    } else {
      // Check if there's a stored shop domain (for development/testing)
      const storedShop = localStorage.getItem('shopDomain');
      if (storedShop) {
        setShopDomain(storedShop);
      }
    }
    
    setIsLoading(false);
  }, []);

  const login = (shop: string) => {
    const backendUrl = import.meta.env.VITE_API_URL || window.location.origin;
    // Store shop domain for future reference
    localStorage.setItem('shopDomain', shop);
    // Redirect to OAuth
    window.location.href = `${backendUrl}/auth/initiate?shop=${shop}`;
  };

  const logout = () => {
    setShopDomain(null);
    setSessionId(null);
    localStorage.removeItem('shopDomain');
    // Clear URL parameters
    window.history.replaceState({}, document.title, window.location.pathname);
  };

  const isAuthenticated = hasValidSession() || !!shopDomain;

  const value: AuthContextType = {
    shopDomain,
    sessionId,
    isAuthenticated,
    isLoading,
    login,
    logout,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}