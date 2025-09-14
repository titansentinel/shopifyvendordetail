import crypto from 'crypto';
import { storage } from '../storage';
import { logger } from '../utils/logger';
import type { ShopSettings, InsertShopSettings } from '@shared/schema';

export class AuthService {
  private readonly ENCRYPTION_KEY: Buffer;
  private readonly ALGORITHM = 'aes-256-gcm';
  private readonly sessionStore = new Map<string, { shopDomain: string; expiresAt: number }>();

  constructor() {
    if (!process.env.SESSION_SECRET) {
      throw new Error('SESSION_SECRET environment variable is required for secure token encryption');
    }
    
    if (process.env.SESSION_SECRET.length < 16) {
      throw new Error('SESSION_SECRET must be at least 16 characters long');
    }
    
    // Derive 32-byte key from SESSION_SECRET using SHA-256
    this.ENCRYPTION_KEY = crypto.createHash('sha256').update(process.env.SESSION_SECRET).digest();
  }

  encryptToken(token: string): { encrypted: string; iv: string; tag: string } {
    // Use 12-byte IV for GCM mode (best practice)
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv(this.ALGORITHM, this.ENCRYPTION_KEY, iv);
    
    let encrypted = cipher.update(token, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const tag = cipher.getAuthTag();
    
    return {
      encrypted,
      iv: iv.toString('hex'),
      tag: tag.toString('hex'),
    };
  }

  decryptToken(encryptedData: { encrypted: string; iv: string; tag: string }): string {
    const iv = Buffer.from(encryptedData.iv, 'hex');
    const decipher = crypto.createDecipheriv(this.ALGORITHM, this.ENCRYPTION_KEY, iv);
    decipher.setAuthTag(Buffer.from(encryptedData.tag, 'hex'));
    
    let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }

  async storeShopCredentials(
    shopDomain: string,
    accessToken: string,
    scope?: string
  ): Promise<ShopSettings> {
    try {
      // Encrypt the access token
      const encryptionResult = this.encryptToken(accessToken);
      const encryptedToken = JSON.stringify(encryptionResult);

      // Check if shop already exists
      const existingShop = await storage.getShopSettings(shopDomain);

      if (existingShop) {
        // Update existing shop - only store encrypted token
        return storage.updateShopSettings(shopDomain, {
          accessToken: process.env.NODE_ENV === 'development' ? accessToken : null,
          encryptedToken,
          tokenScope: scope,
        });
      } else {
        // Create new shop - only store encrypted token in production
        const shopData: InsertShopSettings = {
          shopDomain,
          accessToken: process.env.NODE_ENV === 'development' ? accessToken : null,
          encryptedToken,
          tokenScope: scope,
          showVendorColumn: true,
        };

        return storage.createShopSettings(shopData);
      }
    } catch (error) {
      logger.error('Failed to store shop credentials', {
        shopDomain,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      throw error;
    }
  }

  async getShopCredentials(shopDomain: string): Promise<{
    accessToken: string;
    scope?: string;
  } | null> {
    try {
      const shopSettings = await storage.getShopSettings(shopDomain);
      
      if (!shopSettings) {
        return null;
      }

      // For development, return plain text token if available
      if (process.env.NODE_ENV === 'development' && shopSettings.accessToken) {
        return {
          accessToken: shopSettings.accessToken,
          scope: shopSettings.tokenScope || undefined,
        };
      }

      // Decrypt the token (production or fallback)
      if (shopSettings.encryptedToken) {
        const encryptedData = JSON.parse(shopSettings.encryptedToken);
        const accessToken = this.decryptToken(encryptedData);
        
        return {
          accessToken,
          scope: shopSettings.tokenScope || undefined,
        };
      }

      return null;
    } catch (error) {
      logger.error('Failed to retrieve shop credentials', {
        shopDomain,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      return null;
    }
  }

  async validateShopAccess(shopDomain: string): Promise<boolean> {
    try {
      const credentials = await this.getShopCredentials(shopDomain);
      return credentials !== null;
    } catch (error) {
      logger.error('Failed to validate shop access', {
        shopDomain,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      return false;
    }
  }

  async revokeShopAccess(shopDomain: string): Promise<void> {
    try {
      await storage.updateShopSettings(shopDomain, {
        accessToken: null,
        encryptedToken: null,
        tokenScope: null,
      });

      logger.info('Shop access revoked', { shopDomain });
    } catch (error) {
      logger.error('Failed to revoke shop access', {
        shopDomain,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      throw error;
    }
  }

  generateShopifyAuthUrl(shopDomain: string, clientId: string, redirectUri: string, scopes: string[]): { authUrl: string; state: string } {
    const state = crypto.randomBytes(32).toString('hex');
    const params = new URLSearchParams({
      client_id: clientId,
      scope: scopes.join(','),
      redirect_uri: redirectUri,
      state,
    });

    const authUrl = `https://${shopDomain}/admin/oauth/authorize?${params.toString()}`;
    
    // Store state for validation (with expiration)
    this.sessionStore.set(`state:${state}`, { 
      shopDomain, 
      expiresAt: Date.now() + (10 * 60 * 1000) // 10 minutes
    });
    
    return { authUrl, state };
  }

  validateState(state: string, shopDomain: string): boolean {
    if (!state) return false;
    
    const stateData = this.sessionStore.get(`state:${state}`);
    if (!stateData) return false;
    
    if (Date.now() > stateData.expiresAt) {
      this.sessionStore.delete(`state:${state}`);
      return false;
    }
    
    if (stateData.shopDomain !== shopDomain) {
      return false;
    }
    
    // Clean up used state
    this.sessionStore.delete(`state:${state}`);
    return true;
  }

  validateShopifyHmac(queryString: string, receivedSignature: string): boolean {
    if (!process.env.SHOPIFY_CLIENT_SECRET) {
      logger.error('SHOPIFY_CLIENT_SECRET not configured for HMAC validation');
      return false;
    }
    
    // Remove hmac and signature from query string for validation
    const params = new URLSearchParams(queryString);
    params.delete('hmac');
    params.delete('signature');
    
    // Sort parameters and create query string
    const sortedParams = Array.from(params.entries())
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, value]) => `${key}=${value}`)
      .join('&');
    
    const hmac = crypto
      .createHmac('sha256', process.env.SHOPIFY_CLIENT_SECRET)
      .update(sortedParams, 'utf8')
      .digest('hex');
    
    return crypto.timingSafeEqual(
      Buffer.from(hmac, 'hex'),
      Buffer.from(receivedSignature, 'hex')
    );
  }

  async exchangeCodeForToken(
    shopDomain: string,
    code: string,
    clientId: string,
    clientSecret: string
  ): Promise<{ access_token: string; scope: string }> {
    try {
      const response = await fetch(`https://${shopDomain}/admin/oauth/access_token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          client_id: clientId,
          client_secret: clientSecret,
          code,
        }),
      });

      if (!response.ok) {
        throw new Error(`OAuth token exchange failed: ${response.status} ${response.statusText}`);
      }

      const tokenData = await response.json();
      
      logger.info('OAuth token exchange successful', {
        shopDomain,
        scope: tokenData.scope,
      });

      return tokenData;
    } catch (error) {
      logger.error('OAuth token exchange failed', {
        shopDomain,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      throw error;
    }
  }

  // Session management methods
  createSession(shopDomain: string): string {
    const sessionId = crypto.randomBytes(32).toString('hex');
    const expiresAt = Date.now() + (24 * 60 * 60 * 1000); // 24 hours
    
    this.sessionStore.set(sessionId, { shopDomain, expiresAt });
    this.cleanupExpiredSessions();
    
    logger.info('Session created', { sessionId, shopDomain });
    return sessionId;
  }

  validateSession(sessionId: string): string | null {
    if (!sessionId) return null;
    
    const session = this.sessionStore.get(sessionId);
    if (!session) return null;
    
    if (Date.now() > session.expiresAt) {
      this.sessionStore.delete(sessionId);
      return null;
    }
    
    return session.shopDomain;
  }

  revokeSession(sessionId: string): void {
    this.sessionStore.delete(sessionId);
    logger.info('Session revoked', { sessionId });
  }

  private cleanupExpiredSessions(): void {
    const now = Date.now();
    for (const [sessionId, session] of Array.from(this.sessionStore.entries())) {
      if (now > session.expiresAt) {
        this.sessionStore.delete(sessionId);
      }
    }
  }
}

export const authService = new AuthService();
