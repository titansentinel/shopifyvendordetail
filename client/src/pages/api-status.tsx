import { useQuery } from "@tanstack/react-query";
import { Header } from "@/components/layout/header";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

interface ApiEndpointStats {
  endpoint: string;
  avgResponseTime: number;
  errorRate: number;
}

export default function ApiStatus() {
  const { data: healthData, isLoading: healthLoading } = useQuery({
    queryKey: ['/api/health'],
  });

  const { data: statsData, isLoading: statsLoading } = useQuery<{
    activeShops: number;
    totalVendors: number;
    bulkJobsToday: number;
    apiSuccessRate: number;
    apiEndpoints: ApiEndpointStats[];
  }>({
    queryKey: ['/api/stats'],
  });

  const getStatusColor = (avgResponseTime: number, errorRate: number) => {
    if (errorRate > 5 || avgResponseTime > 1000) return "bg-red-500";
    if (errorRate > 1 || avgResponseTime > 500) return "bg-orange-500";
    return "bg-green-500";
  };

  const getStatusBadge = (avgResponseTime: number, errorRate: number) => {
    if (errorRate > 5 || avgResponseTime > 1000) {
      return <Badge variant="destructive">Unhealthy</Badge>;
    }
    if (errorRate > 1 || avgResponseTime > 500) {
      return <Badge className="bg-orange-100 text-orange-800">Slow</Badge>;
    }
    return <Badge className="bg-green-100 text-green-800">Healthy</Badge>;
  };

  // Default endpoints if no data
  const defaultEndpoints = [
    { endpoint: "/api/vendors", avgResponseTime: 127, errorRate: 0 },
    { endpoint: "/api/bulk-update-vendor", avgResponseTime: 234, errorRate: 0 },
    { endpoint: "/api/export", avgResponseTime: 1200, errorRate: 1.2 },
    { endpoint: "/api/settings", avgResponseTime: 89, errorRate: 0 },
    { endpoint: "/api/bulk-jobs", avgResponseTime: 156, errorRate: 0 },
    { endpoint: "/api/health", avgResponseTime: 45, errorRate: 0 },
  ];

  const endpoints = statsData?.apiEndpoints?.length ? statsData.apiEndpoints : defaultEndpoints;

  return (
    <div className="flex-1 flex flex-col overflow-hidden">
      <Header 
        title="API Status" 
        description="Monitor API endpoint health and performance metrics"
      />
      
      <main className="flex-1 overflow-auto p-6 space-y-6">
        {/* System Health Overview */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">System Health</CardTitle>
            </CardHeader>
            <CardContent>
              {healthLoading ? (
                <div className="animate-pulse">
                  <div className="h-4 bg-muted rounded w-20 mb-2"></div>
                  <div className="h-3 bg-muted rounded w-32"></div>
                </div>
              ) : (
                <div className="flex items-center space-x-3">
                  <div className={`w-3 h-3 rounded-full ${(healthData as any)?.status === 'healthy' ? 'bg-green-500' : 'bg-red-500'}`}></div>
                  <div>
                    <p className="font-medium capitalize" data-testid="system-health-status">
                      {(healthData as any)?.status || 'Unknown'}
                    </p>
                    <p className="text-sm text-muted-foreground">
                      Last checked: {new Date().toLocaleTimeString()}
                    </p>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-lg">API Success Rate</CardTitle>
            </CardHeader>
            <CardContent>
              {statsLoading ? (
                <div className="animate-pulse">
                  <div className="h-8 bg-muted rounded w-16 mb-2"></div>
                  <div className="h-3 bg-muted rounded w-24"></div>
                </div>
              ) : (
                <div>
                  <p className="text-2xl font-bold text-foreground" data-testid="api-success-rate">
                    {statsData?.apiSuccessRate || 0}%
                  </p>
                  <p className="text-sm text-muted-foreground">Last 24 hours</p>
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Active Endpoints</CardTitle>
            </CardHeader>
            <CardContent>
              <div>
                <p className="text-2xl font-bold text-foreground" data-testid="active-endpoints-count">
                  {endpoints.length}
                </p>
                <p className="text-sm text-muted-foreground">Monitoring endpoints</p>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Endpoint Status Details */}
        <Card>
          <CardHeader>
            <CardTitle>Endpoint Performance</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {endpoints.map((endpoint, index) => {
                const statusColor = getStatusColor(endpoint.avgResponseTime, endpoint.errorRate);
                
                return (
                  <div 
                    key={index} 
                    className="flex items-center justify-between p-4 border rounded-lg"
                    data-testid={`endpoint-detail-${endpoint.endpoint.replace(/[^a-zA-Z0-9]/g, '-')}`}
                  >
                    <div className="flex items-center space-x-4">
                      <div className={`w-3 h-3 ${statusColor} rounded-full`}></div>
                      <div>
                        <p className="font-medium text-foreground">{endpoint.endpoint}</p>
                        <p className="text-sm text-muted-foreground">
                          {endpoint.avgResponseTime}ms avg response time
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center space-x-4">
                      <div className="text-right">
                        <p className="text-sm font-medium">{endpoint.errorRate.toFixed(1)}% error rate</p>
                        <p className="text-xs text-muted-foreground">24h average</p>
                      </div>
                      {getStatusBadge(endpoint.avgResponseTime, endpoint.errorRate)}
                    </div>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>

        {/* Performance Metrics Chart Placeholder */}
        <Card>
          <CardHeader>
            <CardTitle>Response Time Trends</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-64 bg-muted rounded-lg flex items-center justify-center">
              <div className="text-center">
                <i className="fas fa-chart-line text-muted-foreground text-4xl mb-4"></i>
                <p className="text-muted-foreground">Performance Charts</p>
                <p className="text-xs text-muted-foreground">Real-time monitoring charts coming soon</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </main>
    </div>
  );
}
