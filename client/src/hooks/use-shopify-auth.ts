import { useState, useCallback } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";

interface ShopAuthStatus {
  isAuthenticated: boolean;
  shopDomain?: string;
  scope?: string;
}

export function useShopifyAuth() {
  const [currentShop, setCurrentShop] = useState<string>("");

  const validateShopMutation = useMutation({
    mutationFn: async (shopDomain: string) => {
      const response = await apiRequest("GET", `/api/settings?shopDomain=${shopDomain}`);
      return response.json();
    },
  });

  const checkAuthStatus = useCallback(async (shopDomain: string): Promise<ShopAuthStatus> => {
    try {
      // Get session from URL parameters
      const urlParams = new URLSearchParams(window.location.search);
      const session = urlParams.get('session');
      
      if (session) {
        // Validate session with backend
        const response = await apiRequest("GET", `/api/settings?shopDomain=${shopDomain}&session=${session}`);
        return {
          isAuthenticated: true,
          shopDomain,
        };
      } else {
        await validateShopMutation.mutateAsync(shopDomain);
        return {
          isAuthenticated: true,
          shopDomain,
        };
      }
    } catch (error) {
      return {
        isAuthenticated: false,
        shopDomain,
      };
    }
  }, [validateShopMutation]);

  const initiateAuth = useCallback((shopDomain: string) => {
    // Redirect directly to backend OAuth initiation
    const backendUrl = import.meta.env.VITE_API_URL || window.location.origin;
    window.location.href = `${backendUrl}/auth/initiate?shop=${shopDomain}`;
  }, []);

  return {
    currentShop,
    setCurrentShop,
    checkAuthStatus,
    initiateAuth,
    isValidating: validateShopMutation.isPending,
  };
}
