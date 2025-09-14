import { useQuery } from "@tanstack/react-query";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useAuth } from "@/contexts/auth-context";
import { apiRequest } from "@/lib/queryClient";
import type { BulkJob } from "@shared/schema";

export function BulkJobsTable() {
  const { shopDomain, isAuthenticated } = useAuth();
  
  const { data, isLoading } = useQuery<{ jobs: BulkJob[] }>({
    queryKey: ['/api/bulk-jobs', shopDomain],
    queryFn: async () => {
      if (!shopDomain) throw new Error('Shop domain is required');
      const response = await apiRequest("GET", `/api/bulk-jobs?shopDomain=${shopDomain}`);
      return response.json();
    },
    enabled: isAuthenticated && !!shopDomain,
  });

  if (isLoading) {
    return (
      <div className="lg:col-span-2 bg-card rounded-lg border border-border">
        <div className="p-6 border-b border-border">
          <h3 className="text-lg font-semibold text-foreground">Recent Bulk Jobs</h3>
        </div>
        <div className="p-6 space-y-4">
          {[...Array(3)].map((_, i) => (
            <div key={i} className="animate-pulse flex space-x-4">
              <div className="h-4 bg-muted rounded flex-1"></div>
              <div className="h-4 bg-muted rounded w-20"></div>
            </div>
          ))}
        </div>
      </div>
    );
  }

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
    <div className="lg:col-span-2 bg-card rounded-lg border border-border">
      <div className="p-6 border-b border-border">
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-semibold text-foreground">Recent Bulk Jobs</h3>
          <Button variant="ghost" size="sm" className="text-primary hover:text-primary/80">
            View All
          </Button>
        </div>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead className="bg-muted">
            <tr>
              <th className="text-left p-4 text-sm font-medium text-muted-foreground">Job ID</th>
              <th className="text-left p-4 text-sm font-medium text-muted-foreground">Shop</th>
              <th className="text-left p-4 text-sm font-medium text-muted-foreground">Products</th>
              <th className="text-left p-4 text-sm font-medium text-muted-foreground">Target Vendor</th>
              <th className="text-left p-4 text-sm font-medium text-muted-foreground">Status</th>
              <th className="text-left p-4 text-sm font-medium text-muted-foreground">Created</th>
            </tr>
          </thead>
          <tbody>
            {data?.jobs?.length === 0 ? (
              <tr>
                <td colSpan={6} className="p-8 text-center text-muted-foreground">
                  No bulk jobs found
                </td>
              </tr>
            ) : (
              data?.jobs?.map((job) => (
                <tr key={job.id} className="border-b border-border hover:bg-muted/50" data-testid={`job-row-${job.id}`}>
                  <td className="p-4 text-sm font-mono text-foreground">#{job.id.slice(0, 12)}</td>
                  <td className="p-4 text-sm text-foreground">{job.shopDomain}</td>
                  <td className="p-4 text-sm text-foreground">{job.totalCount}</td>
                  <td className="p-4 text-sm text-foreground">{job.targetVendor}</td>
                  <td className="p-4">
                    {getStatusBadge(job.status)}
                  </td>
                  <td className="p-4 text-sm text-muted-foreground">{formatTimeAgo(job.createdAt!)}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
