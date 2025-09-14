import { Switch, Route } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { AppLayout } from "@/components/layout/app-layout";
import { AuthProvider } from "@/contexts/auth-context";
import { AuthGuard } from "@/components/auth/auth-guard";
import Dashboard from "@/pages/dashboard";
import BulkJobs from "@/pages/bulk-jobs";
import ApiStatus from "@/pages/api-status";
import Vendors from "@/pages/vendors";
import Settings from "@/pages/settings";
import Logs from "@/pages/logs";
import NotFound from "@/pages/not-found";

function Router() {
  return (
    <AuthGuard>
      <AppLayout>
        <Switch>
          <Route path="/" component={Dashboard} />
          <Route path="/bulk-jobs" component={BulkJobs} />
          <Route path="/api-status" component={ApiStatus} />
          <Route path="/vendors" component={Vendors} />
          <Route path="/settings" component={Settings} />
          <Route path="/logs" component={Logs} />
          <Route component={NotFound} />
        </Switch>
      </AppLayout>
    </AuthGuard>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <TooltipProvider>
          <Toaster />
          <Router />
        </TooltipProvider>
      </AuthProvider>
    </QueryClientProvider>
  );
}

export default App;
