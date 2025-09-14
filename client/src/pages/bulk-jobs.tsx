import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Header } from "@/components/layout/header";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import type { BulkJob } from "@shared/schema";

export default function BulkJobs() {
  const [shopDomain, setShopDomain] = useState("");
  const [productIds, setProductIds] = useState("");
  const [targetVendor, setTargetVendor] = useState("");
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: jobsData, isLoading } = useQuery<{ jobs: BulkJob[] }>({
    queryKey: ['/api/bulk-jobs'],
  });

  const createJobMutation = useMutation({
    mutationFn: async (data: { shopDomain: string; productIds: string[]; vendor: string }) => {
      const response = await apiRequest("POST", "/api/bulk-update-vendor", data);
      return response.json();
    },
    onSuccess: () => {
      toast({
        title: "Bulk job created",
        description: "Your bulk vendor update job has been started",
      });
      queryClient.invalidateQueries({ queryKey: ['/api/bulk-jobs'] });
      setShopDomain("");
      setProductIds("");
      setTargetVendor("");
    },
    onError: (error) => {
      toast({
        title: "Failed to create job",
        description: error instanceof Error ? error.message : "Unknown error",
        variant: "destructive",
      });
    },
  });

  const retryJobMutation = useMutation({
    mutationFn: async (jobId: string) => {
      const response = await apiRequest("POST", `/api/bulk-jobs/${jobId}/retry`);
      return response.json();
    },
    onSuccess: () => {
      toast({
        title: "Job retry initiated",
        description: "The job has been queued for retry",
      });
      queryClient.invalidateQueries({ queryKey: ['/api/bulk-jobs'] });
    },
    onError: (error) => {
      toast({
        title: "Retry failed",
        description: error instanceof Error ? error.message : "Unknown error",
        variant: "destructive",
      });
    },
  });

  const cancelJobMutation = useMutation({
    mutationFn: async (jobId: string) => {
      const response = await apiRequest("POST", `/api/bulk-jobs/${jobId}/cancel`);
      return response.json();
    },
    onSuccess: () => {
      toast({
        title: "Job cancelled",
        description: "The job has been cancelled successfully",
      });
      queryClient.invalidateQueries({ queryKey: ['/api/bulk-jobs'] });
    },
    onError: (error) => {
      toast({
        title: "Cancel failed",
        description: error instanceof Error ? error.message : "Unknown error",
        variant: "destructive",
      });
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!shopDomain || !productIds || !targetVendor) {
      toast({
        title: "Missing required fields",
        description: "Please fill in all required fields",
        variant: "destructive",
      });
      return;
    }

    const productIdList = productIds
      .split('\n')
      .map(id => id.trim())
      .filter(id => id.length > 0);

    createJobMutation.mutate({
      shopDomain,
      productIds: productIdList,
      vendor: targetVendor,
    });
  };

  const getStatusBadge = (status: BulkJob['status']) => {
    const statusStyles = {
      SUCCESS: "bg-green-100 text-green-800",
      RUNNING: "bg-orange-100 text-orange-800", 
      PENDING: "bg-blue-100 text-blue-800",
      FAILED: "bg-red-100 text-red-800"
    };

    if (!status) return <Badge>Unknown</Badge>;

    return (
      <Badge className={`px-2 py-1 text-xs font-medium rounded-full ${statusStyles[status]}`}>
        {status}
      </Badge>
    );
  };

  const formatTimeAgo = (date: Date | string) => {
    const now = new Date();
    const then = new Date(date);
    const diffMs = now.getTime() - then.getTime();
    const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
    const diffMinutes = Math.floor(diffMs / (1000 * 60));

    if (diffHours > 0) {
      return `${diffHours} hours ago`;
    } else if (diffMinutes > 0) {
      return `${diffMinutes} min ago`;
    } else {
      return 'Just now';
    }
  };

  return (
    <div className="flex-1 flex flex-col overflow-hidden">
      <Header 
        title="Bulk Jobs" 
        description="Manage and monitor bulk vendor update operations"
      />
      
      <main className="flex-1 overflow-auto p-6 space-y-6">
        {/* Create New Job Form */}
        <Card>
          <CardHeader>
            <CardTitle>Create New Bulk Job</CardTitle>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <Label htmlFor="shopDomain">Shop Domain</Label>
                  <Input
                    id="shopDomain"
                    placeholder="example.myshopify.com"
                    value={shopDomain}
                    onChange={(e) => setShopDomain(e.target.value)}
                    data-testid="input-shop-domain"
                  />
                </div>
                <div>
                  <Label htmlFor="targetVendor">Target Vendor</Label>
                  <Input
                    id="targetVendor"
                    placeholder="Nike"
                    value={targetVendor}
                    onChange={(e) => setTargetVendor(e.target.value)}
                    data-testid="input-target-vendor"
                  />
                </div>
              </div>
              <div>
                <Label htmlFor="productIds">Product IDs (one per line)</Label>
                <Textarea
                  id="productIds"
                  placeholder="gid://shopify/Product/123&#10;gid://shopify/Product/456"
                  value={productIds}
                  onChange={(e) => setProductIds(e.target.value)}
                  rows={6}
                  data-testid="textarea-product-ids"
                />
              </div>
              <Button 
                type="submit" 
                disabled={createJobMutation.isPending}
                data-testid="button-create-job"
              >
                {createJobMutation.isPending ? "Creating..." : "Create Bulk Job"}
              </Button>
            </form>
          </CardContent>
        </Card>

        {/* Jobs List */}
        <Card>
          <CardHeader>
            <CardTitle>All Bulk Jobs</CardTitle>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <div className="space-y-4">
                {[...Array(3)].map((_, i) => (
                  <div key={i} className="animate-pulse border rounded-lg p-4">
                    <div className="h-4 bg-muted rounded w-1/3 mb-2"></div>
                    <div className="h-3 bg-muted rounded w-1/2"></div>
                  </div>
                ))}
              </div>
            ) : jobsData?.jobs?.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                No bulk jobs found
              </div>
            ) : (
              <div className="space-y-4">
                {jobsData?.jobs?.map((job) => (
                  <div key={job.id} className="border rounded-lg p-4" data-testid={`job-card-${job.id}`}>
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center space-x-2">
                        <span className="font-mono text-sm">#{job.id.slice(0, 12)}</span>
                        {getStatusBadge(job.status)}
                      </div>
                      <div className="flex space-x-2">
                        {job.status === 'FAILED' && (
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => retryJobMutation.mutate(job.id)}
                            disabled={retryJobMutation.isPending}
                            data-testid={`button-retry-${job.id}`}
                          >
                            Retry
                          </Button>
                        )}
                        {(job.status === 'PENDING' || job.status === 'RUNNING') && (
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => cancelJobMutation.mutate(job.id)}
                            disabled={cancelJobMutation.isPending}
                            data-testid={`button-cancel-${job.id}`}
                          >
                            Cancel
                          </Button>
                        )}
                      </div>
                    </div>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                      <div>
                        <span className="text-muted-foreground">Shop:</span>
                        <p className="font-medium">{job.shopDomain}</p>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Target Vendor:</span>
                        <p className="font-medium">{job.targetVendor}</p>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Progress:</span>
                        <p className="font-medium">{job.processedCount || 0}/{job.totalCount}</p>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Created:</span>
                        <p className="font-medium">{formatTimeAgo(job.createdAt!)}</p>
                      </div>
                    </div>
                    {job.errorMessage && (
                      <div className="mt-2 p-2 bg-red-50 border border-red-200 rounded text-sm text-red-700">
                        Error: {job.errorMessage}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </main>
    </div>
  );
}
