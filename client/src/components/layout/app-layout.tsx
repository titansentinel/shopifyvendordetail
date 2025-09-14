import { useState } from "react";
import { Sidebar } from "./sidebar";

interface AppLayoutProps {
  children: React.ReactNode;
}

export function AppLayout({ children }: AppLayoutProps) {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  return (
    <div className="flex h-screen bg-background">
      <Sidebar isCollapsed={sidebarCollapsed} />
      {children}
    </div>
  );
}
