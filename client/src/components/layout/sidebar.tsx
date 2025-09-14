import { Link, useLocation } from "wouter";
import { cn } from "@/lib/utils";

interface SidebarProps {
  isCollapsed?: boolean;
}

export function Sidebar({ isCollapsed = false }: SidebarProps) {
  const [location] = useLocation();

  const navItems = [
    {
      href: "/",
      icon: "fas fa-tachometer-alt",
      label: "Overview",
      id: "overview"
    },
    {
      href: "/bulk-jobs",
      icon: "fas fa-tasks",
      label: "Bulk Jobs",
      id: "jobs"
    },
    {
      href: "/api-status",
      icon: "fas fa-code",
      label: "API Status",
      id: "api"
    },
    {
      href: "/vendors",
      icon: "fas fa-building",
      label: "Vendors",
      id: "vendors"
    },
    {
      href: "/settings",
      icon: "fas fa-cog",
      label: "Settings",
      id: "settings"
    },
    {
      href: "/logs",
      icon: "fas fa-file-alt",
      label: "Logs",
      id: "logs"
    }
  ];

  return (
    <div className={cn(
      "bg-card border-r border-border sidebar-transition h-full flex flex-col",
      isCollapsed ? "w-16" : "w-64"
    )}>
      {/* Logo Header */}
      <div className="flex items-center justify-between p-6 border-b border-border">
        <div className="flex items-center space-x-3">
          <div className="w-8 h-8 bg-primary rounded-lg flex items-center justify-center">
            <i className="fas fa-shopping-cart text-primary-foreground text-sm"></i>
          </div>
          {!isCollapsed && (
            <div>
              <h1 className="text-lg font-semibold text-foreground">Vendor Restorer</h1>
              <p className="text-xs text-muted-foreground">Admin Dashboard</p>
            </div>
          )}
        </div>
      </div>
      
      {/* Navigation Menu */}
      <nav className="flex-1 p-4 space-y-2">
        {navItems.map((item) => {
          const isActive = location === item.href || (item.href !== "/" && location.startsWith(item.href));
          
          return (
            <Link 
              key={item.id} 
              href={item.href}
              className={cn(
                "flex items-center space-x-3 px-3 py-2 rounded-md transition-colors",
                isActive
                  ? "bg-primary text-primary-foreground"
                  : "text-muted-foreground hover:bg-accent hover:text-accent-foreground"
              )}
              data-testid={`nav-${item.id}`}
            >
              <i className={`${item.icon} w-5`}></i>
              {!isCollapsed && <span>{item.label}</span>}
            </Link>
          );
        })}
      </nav>
      
      {/* Status Footer */}
      <div className="p-4 border-t border-border">
        <div className="flex items-center space-x-2 text-sm">
          <div className="w-2 h-2 bg-green-500 rounded-full pulse-status"></div>
          {!isCollapsed && <span className="text-muted-foreground">System Online</span>}
        </div>
        {!isCollapsed && (
          <div className="text-xs text-muted-foreground mt-1">
            Last update: 2 min ago
          </div>
        )}
      </div>
    </div>
  );
}
