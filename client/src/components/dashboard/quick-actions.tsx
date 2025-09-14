import { Button } from "@/components/ui/button";
import { useToast } from "@/hooks/use-toast";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";

export function QuickActions() {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const refreshCacheMutation = useMutation({
    mutationFn: async () => {
      // Invalidate vendors cache to force refresh
      queryClient.invalidateQueries({ queryKey: ['/api/vendors'] });
      return { success: true };
    },
    onSuccess: () => {
      toast({
        title: "Cache refreshed",
        description: "Vendor lists have been updated",
      });
    },
    onError: () => {
      toast({
        title: "Refresh failed",
        description: "Could not refresh vendor cache",
        variant: "destructive",
      });
    },
  });

  const exportLogsMutation = useMutation({
    mutationFn: async () => {
      const response = await apiRequest("GET", "/api/logs?limit=1000");
      return response.json();
    },
    onSuccess: (data) => {
      // Create and download CSV
      const csvContent = convertLogsToCSV(data.logs);
      downloadCSV(csvContent, "system-logs.csv");
      
      toast({
        title: "Logs exported",
        description: "System logs have been downloaded",
      });
    },
    onError: () => {
      toast({
        title: "Export failed",
        description: "Could not export system logs",
        variant: "destructive",
      });
    },
  });

  const healthCheckMutation = useMutation({
    mutationFn: async () => {
      const response = await apiRequest("GET", "/api/health");
      return response.json();
    },
    onSuccess: (data) => {
      toast({
        title: "Health check complete",
        description: `System status: ${data.status}`,
      });
    },
    onError: () => {
      toast({
        title: "Health check failed",
        description: "System diagnostics failed",
        variant: "destructive",
      });
    },
  });

  const convertLogsToCSV = (logs: any[]) => {
    if (!logs || logs.length === 0) return "";
    
    const headers = ["Timestamp", "Endpoint", "Method", "Status Code", "Response Time", "Shop Domain"];
    const rows = logs.map(log => [
      log.timestamp,
      log.endpoint,
      log.method,
      log.statusCode,
      log.responseTime,
      log.shopDomain || ""
    ]);
    
    return [headers.join(","), ...rows.map(row => row.join(","))].join("\n");
  };

  const downloadCSV = (content: string, filename: string) => {
    const blob = new Blob([content], { type: "text/csv" });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
  };

  const actions = [
    {
      title: "Refresh Cache",
      description: "Update vendor lists",
      icon: "fas fa-sync",
      bgColor: "bg-primary/10",
      iconColor: "text-primary",
      onClick: () => refreshCacheMutation.mutate(),
      isLoading: refreshCacheMutation.isPending,
      testId: "action-refresh-cache"
    },
    {
      title: "Export Logs",
      description: "Download system logs",
      icon: "fas fa-download",
      bgColor: "bg-secondary",
      iconColor: "text-secondary-foreground",
      onClick: () => exportLogsMutation.mutate(),
      isLoading: exportLogsMutation.isPending,
      testId: "action-export-logs"
    },
    {
      title: "Health Check",
      description: "Run diagnostics",
      icon: "fas fa-heartbeat",
      bgColor: "bg-green-100",
      iconColor: "text-green-600",
      onClick: () => healthCheckMutation.mutate(),
      isLoading: healthCheckMutation.isPending,
      testId: "action-health-check"
    },
    {
      title: "New Bulk Job",
      description: "Start vendor update",
      icon: "fas fa-magic",
      bgColor: "bg-accent",
      iconColor: "text-accent-foreground",
      onClick: () => {
        // Navigate to bulk jobs page
        window.location.href = "/bulk-jobs";
      },
      isLoading: false,
      testId: "action-new-bulk-job"
    }
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
      {actions.map((action, index) => (
        <Button
          key={index}
          variant="ghost"
          className="bg-card border border-border rounded-lg p-6 text-left hover:shadow-md transition-shadow h-auto"
          onClick={action.onClick}
          disabled={action.isLoading}
          data-testid={action.testId}
        >
          <div className="flex items-center space-x-3">
            <div className={`w-10 h-10 ${action.bgColor} rounded-lg flex items-center justify-center`}>
              <i className={`${action.icon} ${action.iconColor}`}></i>
            </div>
            <div>
              <h4 className="font-medium text-foreground">{action.title}</h4>
              <p className="text-sm text-muted-foreground">{action.description}</p>
            </div>
          </div>
        </Button>
      ))}
    </div>
  );
}
