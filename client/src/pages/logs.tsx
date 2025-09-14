import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Header } from "@/components/layout/header";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import type { ApiLog } from "@shared/schema";

export default function Logs() {
  const [shopDomain, setShopDomain] = useState("");
  const [limit, setLimit] = useState("100");

  const { data: logsData, isLoading, refetch } = useQuery<{ logs: ApiLog[] }>({
    queryKey: ['/api/logs', shopDomain, limit],
    queryFn: async () => {
      const params = new URLSearchParams();
      if (shopDomain) params.append('shopDomain', shopDomain);
      if (limit) params.append('limit', limit);
      
      const response = await fetch(`/api/logs?${params.toString()}`);
      if (!response.ok) throw new Error('Failed to fetch logs');
      return response.json();
    },
  });

  const getStatusBadge = (statusCode: number | null) => {
    if (!statusCode) return <Badge variant="secondary">Unknown</Badge>;
    
    if (statusCode >= 200 && statusCode < 300) {
      return <Badge className="bg-green-100 text-green-800">Success</Badge>;
    } else if (statusCode >= 400 && statusCode < 500) {
      return <Badge className="bg-orange-100 text-orange-800">Client Error</Badge>;
    } else if (statusCode >= 500) {
      return <Badge variant="destructive">Server Error</Badge>;
    } else {
      return <Badge variant="secondary">{statusCode}</Badge>;
    }
  };

  const getMethodBadge = (method: string) => {
    const methodColors = {
      GET: "bg-blue-100 text-blue-800",
      POST: "bg-green-100 text-green-800",
      PUT: "bg-orange-100 text-orange-800",
      DELETE: "bg-red-100 text-red-800",
      PATCH: "bg-purple-100 text-purple-800",
    };

    return (
      <Badge className={methodColors[method as keyof typeof methodColors] || "bg-gray-100 text-gray-800"}>
        {method}
      </Badge>
    );
  };

  const formatTimeAgo = (timestamp: string | Date) => {
    const timestampStr = typeof timestamp === 'string' ? timestamp : timestamp.toISOString();
    const now = new Date();
    const then = new Date(timestampStr);
    const diffMs = now.getTime() - then.getTime();
    const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
    const diffMinutes = Math.floor(diffMs / (1000 * 60));

    if (diffHours > 0) {
      return `${diffHours}h ago`;
    } else if (diffMinutes > 0) {
      return `${diffMinutes}m ago`;
    } else {
      return 'Just now';
    }
  };

  const handleExportLogs = () => {
    if (!logsData?.logs) return;
    
    const csvContent = convertLogsToCSV(logsData.logs);
    downloadCSV(csvContent, `api-logs-${new Date().toISOString().split('T')[0]}.csv`);
  };

  const convertLogsToCSV = (logs: ApiLog[]) => {
    const headers = ["Timestamp", "Endpoint", "Method", "Status Code", "Response Time (ms)", "Shop Domain", "Error Message"];
    const rows = logs.map(log => [
      log.timestamp,
      log.endpoint,
      log.method,
      log.statusCode || "",
      log.responseTime || "",
      log.shopDomain || "",
      log.errorMessage || ""
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

  return (
    <div className="flex-1 flex flex-col overflow-hidden">
      <Header 
        title="API Logs" 
        description="Monitor API requests and system activity logs"
      />
      
      <main className="flex-1 overflow-auto p-6 space-y-6">
        {/* Filters */}
        <Card>
          <CardHeader>
            <CardTitle>Log Filters</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <Label htmlFor="shopDomain">Shop Domain (Optional)</Label>
                <Input
                  id="shopDomain"
                  placeholder="example.myshopify.com"
                  value={shopDomain}
                  onChange={(e) => setShopDomain(e.target.value)}
                  data-testid="input-shop-domain-filter"
                />
              </div>
              <div>
                <Label htmlFor="limit">Number of Logs</Label>
                <Select value={limit} onValueChange={setLimit}>
                  <SelectTrigger data-testid="select-limit">
                    <SelectValue placeholder="Select limit" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="50">50 logs</SelectItem>
                    <SelectItem value="100">100 logs</SelectItem>
                    <SelectItem value="250">250 logs</SelectItem>
                    <SelectItem value="500">500 logs</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="flex items-end space-x-2">
                <Button 
                  onClick={() => refetch()}
                  disabled={isLoading}
                  data-testid="button-refresh-logs"
                >
                  <i className="fas fa-sync mr-2"></i>
                  Refresh
                </Button>
                <Button 
                  variant="outline"
                  onClick={handleExportLogs}
                  disabled={!logsData?.logs?.length}
                  data-testid="button-export-logs"
                >
                  <i className="fas fa-download mr-2"></i>
                  Export
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Logs Table */}
        <Card>
          <CardHeader>
            <CardTitle>Recent API Logs</CardTitle>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <div className="space-y-4">
                {[...Array(5)].map((_, i) => (
                  <div key={i} className="animate-pulse border rounded-lg p-4">
                    <div className="grid grid-cols-6 gap-4">
                      <div className="h-4 bg-muted rounded"></div>
                      <div className="h-4 bg-muted rounded"></div>
                      <div className="h-4 bg-muted rounded"></div>
                      <div className="h-4 bg-muted rounded"></div>
                      <div className="h-4 bg-muted rounded"></div>
                      <div className="h-4 bg-muted rounded"></div>
                    </div>
                  </div>
                ))}
              </div>
            ) : !logsData?.logs?.length ? (
              <div className="text-center py-8 text-muted-foreground">
                No API logs found
              </div>
            ) : (
              <div className="space-y-2">
                {logsData.logs.map((log) => (
                  <div 
                    key={log.id} 
                    className="border rounded-lg p-4 hover:bg-muted/50"
                    data-testid={`log-entry-${log.id}`}
                  >
                    <div className="grid grid-cols-1 md:grid-cols-6 gap-4 items-center">
                      <div>
                        <div className="font-mono text-sm text-foreground">{log.endpoint}</div>
                        <div className="text-xs text-muted-foreground">
                          {formatTimeAgo(log.timestamp || new Date().toISOString())}
                        </div>
                      </div>
                      <div>
                        {getMethodBadge(log.method)}
                      </div>
                      <div>
                        {getStatusBadge(log.statusCode)}
                      </div>
                      <div className="text-sm">
                        {log.responseTime ? `${log.responseTime}ms` : 'N/A'}
                      </div>
                      <div className="text-sm text-muted-foreground">
                        {log.shopDomain || 'System'}
                      </div>
                      <div>
                        {log.errorMessage && (
                          <div className="text-xs text-red-600 truncate" title={log.errorMessage}>
                            <i className="fas fa-exclamation-triangle mr-1"></i>
                            {log.errorMessage}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Log Statistics */}
        {logsData?.logs?.length && (
          <Card>
            <CardHeader>
              <CardTitle>Log Summary</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div className="text-center p-4 border rounded">
                  <div className="text-2xl font-bold text-foreground" data-testid="stat-total-logs">
                    {logsData.logs.length}
                  </div>
                  <div className="text-sm text-muted-foreground">Total Logs</div>
                </div>
                <div className="text-center p-4 border rounded">
                  <div className="text-2xl font-bold text-green-600" data-testid="stat-success-logs">
                    {logsData.logs.filter(log => log.statusCode && log.statusCode >= 200 && log.statusCode < 300).length}
                  </div>
                  <div className="text-sm text-muted-foreground">Success</div>
                </div>
                <div className="text-center p-4 border rounded">
                  <div className="text-2xl font-bold text-orange-600" data-testid="stat-error-logs">
                    {logsData.logs.filter(log => log.statusCode && log.statusCode >= 400).length}
                  </div>
                  <div className="text-sm text-muted-foreground">Errors</div>
                </div>
                <div className="text-center p-4 border rounded">
                  <div className="text-2xl font-bold text-foreground" data-testid="stat-avg-response-time">
                    {Math.round(logsData.logs.filter(log => log.responseTime).reduce((acc, log) => acc + (log.responseTime || 0), 0) / logsData.logs.filter(log => log.responseTime).length) || 0}ms
                  </div>
                  <div className="text-sm text-muted-foreground">Avg Response</div>
                </div>
              </div>
            </CardContent>
          </Card>
        )}
      </main>
    </div>
  );
}
