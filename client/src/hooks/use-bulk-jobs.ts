import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import type { BulkJob } from "@shared/schema";

interface CreateBulkJobParams {
  shopDomain: string;
  productIds: string[];
  vendor: string;
}

export function useBulkJobs(shopDomain?: string) {
  const queryClient = useQueryClient();

  const { data: jobs, isLoading, error } = useQuery<{ jobs: BulkJob[] }>({
    queryKey: ['/api/bulk-jobs', shopDomain],
    queryFn: async () => {
      const params = shopDomain ? `?shopDomain=${shopDomain}` : '';
      const response = await apiRequest("GET", `/api/bulk-jobs${params}`);
      return response.json();
    },
  });

  const createJobMutation = useMutation({
    mutationFn: async (params: CreateBulkJobParams) => {
      const response = await apiRequest("POST", "/api/bulk-update-vendor", params);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/bulk-jobs'] });
    },
  });

  const retryJobMutation = useMutation({
    mutationFn: async (jobId: string) => {
      const response = await apiRequest("POST", `/api/bulk-jobs/${jobId}/retry`);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/bulk-jobs'] });
    },
  });

  const cancelJobMutation = useMutation({
    mutationFn: async (jobId: string) => {
      const response = await apiRequest("POST", `/api/bulk-jobs/${jobId}/cancel`);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/bulk-jobs'] });
    },
  });

  const getJobStatus = useQuery({
    queryKey: ['/api/bulk-jobs/status'],
    queryFn: async () => {
      const params = shopDomain ? `?shopDomain=${shopDomain}` : '';
      const response = await apiRequest("GET", `/api/bulk-jobs${params}`);
      return response.json();
    },
    refetchInterval: 5000, // Poll every 5 seconds for active jobs
    enabled: !!jobs?.jobs?.some(job => job.status === 'RUNNING' || job.status === 'PENDING'),
  });

  return {
    jobs: jobs?.jobs || [],
    isLoading,
    error,
    createJob: createJobMutation.mutateAsync,
    retryJob: retryJobMutation.mutateAsync,
    cancelJob: cancelJobMutation.mutateAsync,
    isCreating: createJobMutation.isPending,
    isRetrying: retryJobMutation.isPending,
    isCancelling: cancelJobMutation.isPending,
  };
}

export function useBulkJobStatus(jobId: string, enabled = true) {
  return useQuery({
    queryKey: ['/api/bulk-jobs', jobId],
    queryFn: async () => {
      const response = await apiRequest("GET", `/api/bulk-jobs/${jobId}`);
      return response.json();
    },
    refetchInterval: (data) => {
      // Stop polling if job is completed
      if ((data as any)?.job?.status === 'SUCCESS' || (data as any)?.job?.status === 'FAILED') {
        return false;
      }
      return 2000; // Poll every 2 seconds for active jobs
    },
    enabled,
  });
}
