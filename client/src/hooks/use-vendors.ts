import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { hasValidSession } from "@/lib/session";

export function useVendors(shopDomain: string) {
  const queryClient = useQueryClient();

  const { data: vendorsData, isLoading, error } = useQuery<{ vendors: string[] }>({
    queryKey: ['/api/vendors', shopDomain],
    queryFn: async () => {
      if (!shopDomain) throw new Error('Shop domain is required');
      
      // Check if user has valid session, if not redirect to OAuth
      if (!hasValidSession()) {
        const backendUrl = import.meta.env.VITE_API_URL || window.location.origin;
        window.location.href = `${backendUrl}/auth/initiate?shop=${shopDomain}`;
        throw new Error('Redirecting to authentication');
      }
      
      const response = await apiRequest("GET", `/api/vendors?shopDomain=${shopDomain}`);
      return response.json();
    },
    enabled: !!shopDomain,
    retry: (failureCount, error) => {
      // Don't retry on authentication errors
      if (error.message.includes('401') || error.message.includes('Redirecting to authentication')) {
        return false;
      }
      return failureCount < 3;
    },
  });

  const refreshVendorsMutation = useMutation({
    mutationFn: async () => {
      if (!shopDomain) throw new Error('Shop domain is required');
      
      // Check if user has valid session, if not redirect to OAuth
      if (!hasValidSession()) {
        const backendUrl = import.meta.env.VITE_API_URL || window.location.origin;
        window.location.href = `${backendUrl}/auth/initiate?shop=${shopDomain}`;
        throw new Error('Redirecting to authentication');
      }
      
      // Invalidate cache to force refresh from Shopify
      queryClient.removeQueries({ queryKey: ['/api/vendors', shopDomain] });
      const response = await apiRequest("GET", `/api/vendors?shopDomain=${shopDomain}`);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/vendors'] });
    },
    onError: (error: any) => {
      // If it's a 401 error, redirect to OAuth
      if (error.message.includes('401') || error.message.includes('Shop not authenticated')) {
        const backendUrl = import.meta.env.VITE_API_URL || window.location.origin;
        window.location.href = `${backendUrl}/auth/initiate?shop=${shopDomain}`;
      }
    },
  });

  const exportVendorMutation = useMutation({
    mutationFn: async (params: { shopDomain: string; vendor?: string; filters?: any }) => {
      const response = await apiRequest("POST", "/api/export", params);
      return response.json();
    },
  });

  return {
    vendors: vendorsData?.vendors || [],
    isLoading,
    error,
    refreshVendors: refreshVendorsMutation.mutateAsync,
    exportVendor: exportVendorMutation.mutateAsync,
    isRefreshing: refreshVendorsMutation.isPending,
    isExporting: exportVendorMutation.isPending,
  };
}

export function useVendorExport() {
  return useMutation({
    mutationFn: async (params: { 
      shopDomain: string; 
      vendor?: string; 
      filters?: {
        status?: string;
        productType?: string;
      }
    }) => {
      const response = await apiRequest("POST", "/api/export", params);
      return response.json();
    },
  });
}
