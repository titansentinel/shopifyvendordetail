import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Header } from "@/components/layout/header";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import { useVendors } from "@/hooks/use-vendors";

export default function Vendors() {
  const [shopDomain, setShopDomain] = useState("");
  const [exportVendor, setExportVendor] = useState("");
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { vendors, isLoading: vendorsLoading, refreshVendors } = useVendors(shopDomain);

  const exportMutation = useMutation({
    mutationFn: async (data: { shopDomain: string; vendor?: string }) => {
      const response = await apiRequest("POST", "/api/export", data);
      return response.json();
    },
    onSuccess: (data) => {
      // Open download URL in new tab
      window.open(data.downloadUrl, '_blank');
      toast({
        title: "Export created",
        description: "Your CSV export is ready for download",
      });
    },
    onError: (error) => {
      toast({
        title: "Export failed",
        description: error instanceof Error ? error.message : "Unknown error",
        variant: "destructive",
      });
    },
  });

  const handleLoadVendors = () => {
    if (!shopDomain) {
      toast({
        title: "Shop domain required",
        description: "Please enter a shop domain to load vendors",
        variant: "destructive",
      });
      return;
    }
    refreshVendors();
  };

  const handleExport = (vendor?: string) => {
    if (!shopDomain) {
      toast({
        title: "Shop domain required",
        description: "Please enter a shop domain to export",
        variant: "destructive",
      });
      return;
    }

    exportMutation.mutate({
      shopDomain,
      vendor: vendor || undefined,
    });
  };

  const handleExportAll = () => {
    handleExport();
  };

  const handleExportByVendor = () => {
    if (!exportVendor) {
      toast({
        title: "Vendor required",
        description: "Please select a vendor to export",
        variant: "destructive",
      });
      return;
    }
    handleExport(exportVendor);
  };

  return (
    <div className="flex-1 flex flex-col overflow-hidden">
      <Header 
        title="Vendors" 
        description="Manage vendor lists and export product data by vendor"
      />
      
      <main className="flex-1 overflow-auto p-6 space-y-6">
        {/* Shop Domain Input */}
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
                onClick={handleLoadVendors}
                disabled={vendorsLoading || !shopDomain}
                data-testid="button-load-vendors"
              >
                {vendorsLoading ? "Loading..." : "Load Vendors"}
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Vendor List */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle>Vendor List</CardTitle>
              <div className="flex space-x-2">
                <Button
                  variant="outline"
                  onClick={handleLoadVendors}
                  disabled={vendorsLoading || !shopDomain}
                  data-testid="button-refresh-vendors"
                >
                  <i className="fas fa-sync mr-2"></i>
                  Refresh
                </Button>
                <Button
                  onClick={handleExportAll}
                  disabled={exportMutation.isPending || !shopDomain}
                  data-testid="button-export-all"
                >
                  <i className="fas fa-download mr-2"></i>
                  Export All Products
                </Button>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            {!shopDomain ? (
              <div className="text-center py-8 text-muted-foreground">
                Enter a shop domain to load vendors
              </div>
            ) : vendorsLoading ? (
              <div className="space-y-3">
                {[...Array(6)].map((_, i) => (
                  <div key={i} className="animate-pulse flex items-center justify-between p-3 border rounded">
                    <div className="h-4 bg-muted rounded w-32"></div>
                    <div className="h-6 bg-muted rounded w-16"></div>
                  </div>
                ))}
              </div>
            ) : vendors.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                No vendors found for this shop
              </div>
            ) : (
              <div className="space-y-2">
                {vendors.map((vendor, index) => (
                  <div 
                    key={index} 
                    className="flex items-center justify-between p-3 border rounded hover:bg-muted/50"
                    data-testid={`vendor-item-${index}`}
                  >
                    <div className="flex items-center space-x-3">
                      <i className="fas fa-building text-muted-foreground"></i>
                      <span className="font-medium">{vendor}</span>
                    </div>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => handleExport(vendor)}
                      disabled={exportMutation.isPending}
                      data-testid={`button-export-vendor-${index}`}
                    >
                      <i className="fas fa-download mr-1"></i>
                      Export
                    </Button>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Export by Vendor */}
        <Card>
          <CardHeader>
            <CardTitle>Export by Specific Vendor</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-end space-x-4">
              <div className="flex-1">
                <Label htmlFor="exportVendor">Vendor Name</Label>
                <Input
                  id="exportVendor"
                  placeholder="Enter vendor name..."
                  value={exportVendor}
                  onChange={(e) => setExportVendor(e.target.value)}
                  data-testid="input-export-vendor"
                />
              </div>
              <Button 
                onClick={handleExportByVendor}
                disabled={exportMutation.isPending || !shopDomain || !exportVendor}
                data-testid="button-export-by-vendor"
              >
                {exportMutation.isPending ? "Exporting..." : "Export Vendor Products"}
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Vendor Statistics */}
        {vendors.length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle>Vendor Statistics</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="text-center p-4 border rounded">
                  <div className="text-2xl font-bold text-foreground" data-testid="stat-total-vendors">
                    {vendors.length}
                  </div>
                  <div className="text-sm text-muted-foreground">Total Vendors</div>
                </div>
                <div className="text-center p-4 border rounded">
                  <div className="text-2xl font-bold text-foreground">
                    <i className="fas fa-building text-primary"></i>
                  </div>
                  <div className="text-sm text-muted-foreground">Vendor Data Loaded</div>
                </div>
                <div className="text-center p-4 border rounded">
                  <div className="text-2xl font-bold text-foreground">
                    <i className="fas fa-sync text-green-600"></i>
                  </div>
                  <div className="text-sm text-muted-foreground">Cache Updated</div>
                </div>
              </div>
            </CardContent>
          </Card>
        )}
      </main>
    </div>
  );
}
