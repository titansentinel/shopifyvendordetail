import { ReactNode, useState } from 'react';
import { useAuth } from '@/contexts/auth-context';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';

interface AuthGuardProps {
  children: ReactNode;
}

export function AuthGuard({ children }: AuthGuardProps) {
  const { shopDomain, isAuthenticated, isLoading, login } = useAuth();
  const [inputShop, setInputShop] = useState('');

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary mx-auto mb-4"></div>
          <p className="text-muted-foreground">Loading...</p>
        </div>
      </div>
    );
  }

  if (!isAuthenticated || !shopDomain) {
    return (
      <div className="flex items-center justify-center min-h-screen p-4">
        <Card className="w-full max-w-md">
          <CardHeader className="text-center">
            <CardTitle>Connect Your Shopify Store</CardTitle>
            <CardDescription>
              Enter your Shopify store domain to get started with vendor management.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="shop">Store Domain</Label>
              <Input
                id="shop"
                type="text"
                placeholder="your-store.myshopify.com"
                value={inputShop}
                onChange={(e) => setInputShop(e.target.value)}
                onKeyPress={(e) => {
                  if (e.key === 'Enter' && inputShop.trim()) {
                    e.preventDefault();
                    login(inputShop.trim());
                  }
                }}
              />
            </div>
            <Button 
              onClick={() => inputShop.trim() && login(inputShop.trim())}
              className="w-full"
              disabled={!inputShop.trim()}
            >
              Connect Store
            </Button>
            <p className="text-xs text-muted-foreground text-center">
              You'll be redirected to Shopify to authorize this application.
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  return <>{children}</>;
}