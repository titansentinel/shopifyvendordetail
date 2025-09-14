import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Header } from "@/components/layout/header";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Switch } from "@/components/ui/switch";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";

interface ShopSettings {
  shopDomain: string;
  showVendorColumn: boolean;
  lastUpdated: string;
}

export default function Settings() {
  const [shopDomain, setShopDomain] = useState("");
  const [showVendorColumn, setShowVendorColumn] = useState(true);
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: settings, isLoading } = useQuery<ShopSettings>({
    queryKey: ['/api/settings', shopDomain],
    enabled: !!shopDomain,
  });

  const updateSettingsMutation = useMutation({
    mutationFn: async (data: { shopDomain: string; showVendorColumn: boolean }) => {
      const response = await apiRequest("POST", "/api/settings", data);
      return response.json();
    },
    onSuccess: () => {
      toast({
        title: "Settings updated",
        description: "Your shop settings have been saved successfully",
      });
      queryClient.invalidateQueries({ queryKey: ['/api/settings'] });
    },
    onError: (error) => {
      toast({
        title: "Update failed",
        description: error instanceof Error ? error.message : "Unknown error",
        variant: "destructive",
      });
    },
  });

  // Update local state when settings data changes
  useEffect(() => {
    if (settings) {
      setShowVendorColumn(settings.showVendorColumn);
    }
  }, [settings]);

  const handleLoadSettings = () => {
    if (!shopDomain) {
      toast({
        title: "Shop domain required",
        description: "Please enter a shop domain to load settings",
        variant: "destructive",
      });
      return;
    }
    
    queryClient.invalidateQueries({ queryKey: ['/api/settings', shopDomain] });
  };

  const handleSaveSettings = () => {
    if (!shopDomain) {
      toast({
        title: "Shop domain required",
        description: "Please enter a shop domain to save settings",
        variant: "destructive",
      });
      return;
    }

    updateSettingsMutation.mutate({
      shopDomain,
      showVendorColumn,
    });
  };

  return (
    <div className="flex-1 flex flex-col overflow-hidden">
      <Header 
        title="Settings" 
        description="Configure shop preferences and vendor column display options"
      />
      
      <main className="flex-1 overflow-auto p-6 space-y-6">
        {/* Shop Configuration */}
        <Card>
          <CardHeader>
            <CardTitle>Shop Configuration</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-end space-x-4">
              <div className="flex-1">
                <Label htmlFor="shopDomain">Shop Domain</Label>
                <Input
                  id="shopDomain"
                  placeholder="example.myshopify.com"
                  value={shopDomain}
                  onChange={(e) => setShopDomain(e.target.value)}
                  data-testid="input-shop-domain"
                />
              </div>
              <Button 
                onClick={handleLoadSettings}
                disabled={isLoading || !shopDomain}
                data-testid="button-load-settings"
              >
                {isLoading ? "Loading..." : "Load Settings"}
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Vendor Column Settings */}
        <Card>
          <CardHeader>
            <CardTitle>Vendor Column Display</CardTitle>
          </CardHeader>
          <CardContent className="space-y-6">
            {!shopDomain ? (
              <div className="text-center py-8 text-muted-foreground">
                Enter a shop domain to configure settings
              </div>
            ) : isLoading ? (
              <div className="space-y-4">
                <div className="animate-pulse flex items-center justify-between">
                  <div className="h-4 bg-muted rounded w-48"></div>
                  <div className="h-6 bg-muted rounded w-12"></div>
                </div>
              </div>
            ) : (
              <>
                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label htmlFor="showVendorColumn" className="text-base">
                      Show Vendor Column
                    </Label>
                    <div className="text-sm text-muted-foreground">
                      Display the vendor column in the product list interface
                    </div>
                  </div>
                  <Switch
                    id="showVendorColumn"
                    checked={showVendorColumn}
                    onCheckedChange={setShowVendorColumn}
                    data-testid="switch-show-vendor-column"
                  />
                </div>

                <div className="pt-4 border-t">
                  <Button 
                    onClick={handleSaveSettings}
                    disabled={updateSettingsMutation.isPending}
                    data-testid="button-save-settings"
                  >
                    {updateSettingsMutation.isPending ? "Saving..." : "Save Settings"}
                  </Button>
                </div>
              </>
            )}
          </CardContent>
        </Card>

        {/* Current Settings Display */}
        {settings && (
          <Card>
            <CardHeader>
              <CardTitle>Current Settings</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <Label className="text-sm text-muted-foreground">Shop Domain</Label>
                    <p className="font-medium" data-testid="current-shop-domain">{settings.shopDomain}</p>
                  </div>
                  <div>
                    <Label className="text-sm text-muted-foreground">Vendor Column Visible</Label>
                    <p className="font-medium" data-testid="current-vendor-column-status">
                      {settings.showVendorColumn ? "Yes" : "No"}
                    </p>
                  </div>
                  <div>
                    <Label className="text-sm text-muted-foreground">Last Updated</Label>
                    <p className="font-medium" data-testid="current-last-updated">
                      {new Date(settings.lastUpdated).toLocaleString()}
                    </p>
                  </div>
                  <div>
                    <Label className="text-sm text-muted-foreground">Status</Label>
                    <p className="font-medium text-green-600" data-testid="current-settings-status">
                      <i className="fas fa-check-circle mr-1"></i>
                      Active
                    </p>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Settings Information */}
        <Card>
          <CardHeader>
            <CardTitle>About Settings</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3 text-sm text-muted-foreground">
              <p>
                <strong>Vendor Column Display:</strong> Controls whether the vendor column is visible in your Shopify admin product list. When enabled, you can see and manage vendor information directly from the product interface.
              </p>
              <p>
                <strong>Configuration Persistence:</strong> All settings are automatically saved and will persist across sessions. Changes take effect immediately in your Shopify admin interface.
              </p>
              <p>
                <strong>Bulk Operations:</strong> When the vendor column is enabled, you can perform bulk vendor updates and exports directly from the product list interface.
              </p>
            </div>
          </CardContent>
        </Card>
      </main>
    </div>
  );
}
