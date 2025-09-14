import { useQuery } from "@tanstack/react-query";
import { useAuth } from "@/contexts/auth-context";
import { apiRequest } from "@/lib/queryClient";

interface SystemStats {
  activeShops: number;
  totalVendors: number;
  bulkJobsToday: number;
  apiSuccessRate: number;
}

export function StatsGrid() {
  const { shopDomain, isAuthenticated } = useAuth();
  
  const { data: stats, isLoading } = useQuery<{ 
    activeShops: number;
    totalVendors: number;
    bulkJobsToday: number;
    apiSuccessRate: number;
  }>({
    queryKey: ['/api/stats', shopDomain],
    queryFn: async () => {
      if (!shopDomain) throw new Error('Shop domain is required');
      const response = await apiRequest("GET", `/api/stats?shopDomain=${shopDomain}`);
      return response.json();
    },
    enabled: isAuthenticated && !!shopDomain,
  });

  if (isLoading) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {[...Array(4)].map((_, i) => (
          <div key={i} className="bg-card rounded-lg border border-border p-6 animate-pulse">
            <div className="flex items-center justify-between">
              <div className="space-y-2">
                <div className="h-4 bg-muted rounded w-20"></div>
                <div className="h-8 bg-muted rounded w-16"></div>
              </div>
              <div className="w-12 h-12 bg-muted rounded-lg"></div>
            </div>
          </div>
        ))}
      </div>
    );
  }

  const statCards = [
    {
      title: "Active Shops",
      value: stats?.activeShops || 0,
      icon: "fas fa-store",
      bgColor: "bg-primary/10",
      iconColor: "text-primary",
      change: "+12%",
      changeText: "from last month",
      changeColor: "text-green-600"
    },
    {
      title: "Total Vendors", 
      value: stats?.totalVendors || 0,
      icon: "fas fa-building",
      bgColor: "bg-accent/50",
      iconColor: "text-accent-foreground",
      change: "+3.2%",
      changeText: "from last week",
      changeColor: "text-green-600"
    },
    {
      title: "Bulk Jobs Today",
      value: stats?.bulkJobsToday || 0,
      icon: "fas fa-tasks",
      bgColor: "bg-transparent",
      iconColor: "text-blue-600",
      change: "2 pending",
      changeText: "in queue",
      changeColor: "text-orange-600"
    },
    {
      title: "API Success Rate",
      value: `${stats?.apiSuccessRate || 0}%`,
      icon: "fas fa-check-circle",
      bgColor: "bg-transparent",
      iconColor: "text-green-600",
      change: "Excellent",
      changeText: "system health",
      changeColor: "text-green-600"
    }
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
      {statCards.map((stat, index) => (
        <div key={index} className="bg-card rounded-lg border border-border p-6 fade-in">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-muted-foreground">{stat.title}</p>
              <p className="text-2xl font-bold text-foreground" data-testid={`stat-${stat.title.toLowerCase().replace(/\s+/g, '-')}`}>
                {stat.value}
              </p>
            </div>
            <div className={`w-12 h-12 ${stat.bgColor} rounded-lg flex items-center justify-center`}>
              <i className={`${stat.icon} ${stat.iconColor} text-xl`}></i>
            </div>
          </div>
          <div className="mt-4 flex items-center">
            <span className={`${stat.changeColor} text-sm font-medium`}>{stat.change}</span>
            <span className="text-muted-foreground text-sm ml-1">{stat.changeText}</span>
          </div>
        </div>
      ))}
    </div>
  );
}
