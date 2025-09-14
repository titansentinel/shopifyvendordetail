import { Header } from "@/components/layout/header";
import { StatsGrid } from "@/components/dashboard/stats-grid";
import { BulkJobsTable } from "@/components/dashboard/bulk-jobs-table";
import { ApiStatusPanel } from "@/components/dashboard/api-status-panel";
import { QuickActions } from "@/components/dashboard/quick-actions";

export default function Dashboard() {
  return (
    <div className="flex-1 flex flex-col overflow-hidden">
      <Header 
        title="System Overview" 
        description="Monitor and manage your Shopify vendor operations"
      />
      
      <main className="flex-1 overflow-auto p-6 space-y-6">
        {/* Stats Cards */}
        <StatsGrid />
        
        {/* Main Content Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Recent Bulk Jobs */}
          <BulkJobsTable />
          
          {/* API Endpoints Status */}
          <ApiStatusPanel />
        </div>
        
        {/* System Performance Chart - Placeholder */}
        <div className="bg-card rounded-lg border border-border">
          <div className="p-6 border-b border-border">
            <h3 className="text-lg font-semibold text-foreground">System Performance</h3>
            <p className="text-sm text-muted-foreground">API response times and job processing metrics (Last 24 hours)</p>
          </div>
          <div className="p-6">
            <div className="h-64 bg-muted rounded-lg flex items-center justify-center">
              <div className="text-center">
                <i className="fas fa-chart-line text-muted-foreground text-4xl mb-4"></i>
                <p className="text-muted-foreground">Performance Chart</p>
                <p className="text-xs text-muted-foreground">Chart integration coming soon</p>
              </div>
            </div>
          </div>
        </div>
        
        {/* Quick Actions Panel */}
        <QuickActions />
      </main>
    </div>
  );
}
