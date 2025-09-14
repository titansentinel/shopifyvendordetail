import type { Express, Request } from "express";
import { createServer, type Server } from "http";

// Extend Express Request interface to include custom shopDomain property
declare global {
  namespace Express {
    interface Request {
      shopDomain?: string;
    }
  }
}
import { z } from "zod";
import { storage } from "./storage";
import { bulkJobProcessor } from "./services/bulk-jobs";
import { csvExportService } from "./services/csv-export";
import { authService } from "./services/auth";
import { createShopifyService } from "./services/shopify";
import { logger } from "./utils/logger";
import { 
  generalApiLimiter, 
  bulkOperationLimiter, 
  exportLimiter, 
  shopifyApiLimiter 
} from "./middleware/rate-limit";

export async function registerRoutes(app: Express): Promise<Server> {
  // Apply general rate limiting to all API routes
  app.use('/api', generalApiLimiter.middleware());

  // OAuth routes (defined FIRST to avoid /api middleware)
  // OAuth initiation route
  app.get('/auth/initiate', async (req, res) => {
    try {
      const { shop } = req.query;
      
      if (!shop || typeof shop !== 'string') {
        return res.status(400).json({ error: 'Shop domain is required' });
      }

      const clientId = process.env.SHOPIFY_CLIENT_ID || 'your_client_id';
      const redirectUri = `${process.env.NODE_ENV === 'production' ? 
        `https://${req.get('host')}` : 
        `http://${req.get('host')}`}/auth/callback`;
      const scopes = ['read_products', 'write_products'];
      
      const { authUrl } = authService.generateShopifyAuthUrl(
        shop,
        clientId,
        redirectUri,
        scopes
      );

      res.redirect(authUrl);
    } catch (error) {
      logger.error('Failed to initiate OAuth', {
        shop: req.query.shop,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      res.status(500).json({ error: 'Failed to initiate authentication' });
    }
  });

  // OAuth callback route
  app.get('/auth/callback', async (req, res) => {
    try {
      const { code, shop, state, hmac } = req.query;
      
      if (!code || !shop || !state) {
        return res.status(400).json({ error: 'Missing required parameters' });
      }

      // CRITICAL SECURITY: Validate state parameter for CSRF protection
      if (!authService.validateState(state as string, shop as string)) {
        logger.error('OAuth callback - Invalid state parameter', {
          shop: shop as string,
          receivedState: state as string,
        });
        return res.status(400).json({ error: 'Invalid state parameter - potential CSRF attack' });
      }

      // CRITICAL SECURITY: Require and validate HMAC signature for request authenticity
      if (!hmac) {
        logger.error('OAuth callback - Missing HMAC signature', {
          shop: shop as string,
        });
        return res.status(400).json({ error: 'Missing HMAC signature - request not authenticated' });
      }
      
      if (!authService.validateShopifyHmac(req.url?.split('?')[1] || '', hmac as string)) {
        logger.error('OAuth callback - Invalid HMAC signature', {
          shop: shop as string,
        });
        return res.status(400).json({ error: 'Invalid request signature' });
      }

      const clientId = process.env.SHOPIFY_CLIENT_ID || 'your_client_id';
      const clientSecret = process.env.SHOPIFY_CLIENT_SECRET || 'your_client_secret';
      
      const tokenData = await authService.exchangeCodeForToken(
        shop as string,
        code as string,
        clientId,
        clientSecret
      );

      // Store the shop credentials (includes access token storage)
      await authService.storeShopCredentials(
        shop as string,
        tokenData.access_token,
        tokenData.scope
      );

      // Create session for the authenticated shop
      const sessionId = authService.createSession(shop as string);
      
      logger.authSuccess(shop as string, tokenData.scope);

      // Redirect to frontend with session - fix route to match App.tsx
      const frontendUrl = process.env.FRONTEND_URL || `${req.protocol}://${req.get('host')}`;
      res.redirect(`${frontendUrl}/?shop=${shop}&session=${sessionId}&installed=true`);
    } catch (error) {
      logger.authFailure(
        req.query.shop as string || 'unknown',
        error instanceof Error ? error.message : 'Unknown error'
      );
      res.status(500).json({ error: 'Authentication failed' });
    }
  });

  // Authentication middleware for protected API routes
  const requireShopAuth = async (req: any, res: any, next: any) => {
    // Skip auth for truly public endpoints
    const publicEndpoints = [
      '/api/health'
    ];
    
    if (publicEndpoints.includes(req.path)) {
      return next();
    }

    // SECURITY FIX: All protected endpoints now require valid session
    // Check if path matches protected patterns (including dynamic routes)
    const protectedPatterns = [
      '/api/vendors',
      '/api/settings', 
      '/api/bulk-jobs', // This covers /api/bulk-jobs/:id too
      '/api/bulk-update-vendor',
      '/api/export', // This covers both /api/export and /api/export/download
      '/api/stats',
      '/api/logs'
    ];
    
    const isProtectedEndpoint = protectedPatterns.some(pattern => 
      req.path === pattern || req.path.startsWith(pattern + '/')
    );
    
    if (!isProtectedEndpoint) {
      return next();
    }

    // SECURITY FIX: Require valid session for ALL protected endpoints
    // Accept both 'shop' and 'shopDomain' for consistency with frontend
    const { shop, shopDomain, session } = req.query;
    const clientShopDomain = shop || shopDomain;
    
    if (!clientShopDomain || !session) {
      return res.status(401).json({ 
        error: 'Authentication required. Shop domain and session are required.',
        code: 'MISSING_SESSION'
      });
    }

    // Validate session and ensure it matches the shop
    const sessionShopDomain = authService.validateSession(session as string);
    
    if (!sessionShopDomain || sessionShopDomain !== clientShopDomain) {
      return res.status(401).json({ 
        error: 'Invalid or expired session. Please re-authenticate.',
        code: 'INVALID_SESSION'
      });
    }

    // Additional security: Verify shop still has valid access tokens
    const hasValidAccess = await authService.validateShopAccess(sessionShopDomain);
    if (!hasValidAccess) {
      return res.status(401).json({ 
        error: 'Shop authentication expired. Please complete OAuth setup again.',
        code: 'EXPIRED_CREDENTIALS'
      });
    }

    req.shopDomain = sessionShopDomain;
    next();
  };

  // Apply auth middleware to protected API routes (excluding auth routes)
  app.use('/api', (req: any, res: any, next: any) => {
    // Skip auth middleware for OAuth routes
    if (req.path.startsWith('/api/auth/')) {
      return next();
    }
    return requireShopAuth(req, res, next);
  });

  // Middleware to log API calls
  app.use('/api', async (req, res, next) => {
    const start = Date.now();
    
    res.on('finish', async () => {
      const responseTime = Date.now() - start;
      
      try {
        await storage.createApiLog({
          endpoint: req.path,
          method: req.method,
          statusCode: res.statusCode,
          responseTime,
          shopDomain: req.shopDomain!,
          errorMessage: res.statusCode >= 400 ? res.statusMessage : undefined,
        });
      } catch (error) {
        logger.error('Failed to log API call', {
          error: error instanceof Error ? error.message : 'Unknown error',
        });
      }
    });

    next();
  });

  // Health check endpoint
  app.get('/api/health', async (req, res) => {
    try {
      const stats = await storage.getSystemStats();
      res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        stats,
      });
    } catch (error) {
      logger.error('Health check failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      res.status(500).json({
        status: 'unhealthy',
        error: 'Database connection failed',
      });
    }
  });

  // Get distinct vendor list (cached)
  app.get('/api/vendors', shopifyApiLimiter.middleware(), async (req, res) => {
    try {
      // SECURITY FIX: Use authenticated shop domain from middleware
      const shopDomain = req.shopDomain!;

      // Get cached vendors from database
      let vendors = await storage.getVendors(shopDomain);
      
      // If no vendors in cache or cache is old, refresh from Shopify
      if (vendors.length === 0) {
        const shopSettings = await storage.getShopSettings(shopDomain);
        
        if (!shopSettings?.accessToken) {
          return res.status(401).json({ error: 'Shop not authenticated' });
        }

        const shopifyService = createShopifyService(shopDomain, shopSettings.accessToken);
        const shopifyVendors = await shopifyService.getAllVendors();
        
        // Update vendor cache
        for (const vendorName of shopifyVendors) {
          const existingVendor = await storage.getVendorByName(shopDomain, vendorName);
          
          if (!existingVendor) {
            await storage.createVendor({
              shopDomain,
              name: vendorName,
              productCount: 0,
            });
          }
        }
        
        vendors = await storage.getVendors(shopDomain);
      }

      res.json({ vendors: vendors.map(v => v.name) });
    } catch (error) {
      logger.error('Failed to get vendors', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      res.status(500).json({ error: 'Failed to fetch vendors' });
    }
  });

  // Bulk update vendor
  app.post('/api/bulk-update-vendor', bulkOperationLimiter.middleware(), async (req, res) => {
    try {
      const schema = z.object({
        productIds: z.array(z.string()).min(1),
        vendor: z.string().min(1),
      });

      const { productIds, vendor } = schema.parse(req.body);
      // SECURITY FIX: Use authenticated shop domain from middleware
      const shopDomain = req.shopDomain!;

      // Create bulk job
      const job = await bulkJobProcessor.createJob({
        shopDomain,
        productIds,
        targetVendor: vendor,
        status: 'PENDING',
        totalCount: productIds.length,
      });

      logger.bulkJobStart(job.id, shopDomain, productIds.length);

      res.json({
        jobId: job.id,
        status: job.status,
        message: 'Bulk update job created successfully',
      });
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({
          error: 'Invalid request data',
          details: error.errors,
        });
      }

      logger.error('Bulk update failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      res.status(500).json({ error: 'Failed to create bulk update job' });
    }
  });

  // Get bulk job status
  app.get('/api/bulk-jobs/:id', async (req, res) => {
    try {
      const { id } = req.params;
      // SECURITY FIX: Use authenticated shop domain from middleware
      const shopDomain = req.shopDomain!;

      // First verify job ownership before returning status
      const job = await bulkJobProcessor.getJob(id);
      
      if (!job) {
        return res.status(404).json({ error: 'Job not found' });
      }

      // SECURITY FIX: Verify job belongs to authenticated shop
      if (job.shopDomain !== shopDomain) {
        logger.error('Bulk job access denied - shop domain mismatch', {
          jobId: id,
          authenticatedShop: shopDomain,
          jobShop: job.shopDomain,
        });
        return res.status(403).json({ 
          error: 'Access denied - job belongs to different shop',
          code: 'CROSS_TENANT_ACCESS_DENIED'
        });
      }

      const jobStatus = await bulkJobProcessor.getJobStatus(id);

      res.json({
        job: jobStatus.job,
        progress: jobStatus.progress,
        isProcessing: jobStatus.isProcessing,
      });
    } catch (error) {
      logger.error('Failed to get job status', {
        jobId: req.params.id,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      res.status(500).json({ error: 'Failed to get job status' });
    }
  });

  // Get recent bulk jobs
  app.get('/api/bulk-jobs', async (req, res) => {
    try {
      const { limit } = req.query;
      // SECURITY FIX: Use authenticated shop domain from middleware
      const shopDomain = req.shopDomain!;
      
      const jobs = await bulkJobProcessor.getRecentJobs(
        shopDomain,
        limit ? parseInt(limit as string) : undefined
      );

      res.json({ jobs });
    } catch (error) {
      logger.error('Failed to get bulk jobs', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      res.status(500).json({ error: 'Failed to fetch bulk jobs' });
    }
  });

  // Retry bulk job
  app.post('/api/bulk-jobs/:id/retry', async (req, res) => {
    try {
      const { id } = req.params;
      // SECURITY FIX: Use authenticated shop domain from middleware
      const shopDomain = req.shopDomain!;

      // First verify job ownership before retrying
      const existingJob = await bulkJobProcessor.getJob(id);
      
      if (!existingJob) {
        return res.status(404).json({ error: 'Job not found' });
      }

      // SECURITY FIX: Verify job belongs to authenticated shop
      if (existingJob.shopDomain !== shopDomain) {
        logger.error('Bulk job retry access denied - shop domain mismatch', {
          jobId: id,
          authenticatedShop: shopDomain,
          jobShop: existingJob.shopDomain,
        });
        return res.status(403).json({ 
          error: 'Access denied - job belongs to different shop',
          code: 'CROSS_TENANT_ACCESS_DENIED'
        });
      }

      const job = await bulkJobProcessor.retryJob(id);
      
      res.json({
        job,
        message: 'Job retry initiated',
      });
    } catch (error) {
      logger.error('Failed to retry job', {
        jobId: req.params.id,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      res.status(400).json({ 
        error: error instanceof Error ? error.message : 'Failed to retry job',
      });
    }
  });

  // Cancel bulk job
  app.post('/api/bulk-jobs/:id/cancel', async (req, res) => {
    try {
      const { id } = req.params;
      // SECURITY FIX: Use authenticated shop domain from middleware
      const shopDomain = req.shopDomain!;

      // First verify job ownership before canceling
      const existingJob = await bulkJobProcessor.getJob(id);
      
      if (!existingJob) {
        return res.status(404).json({ error: 'Job not found' });
      }

      // SECURITY FIX: Verify job belongs to authenticated shop
      if (existingJob.shopDomain !== shopDomain) {
        logger.error('Bulk job cancel access denied - shop domain mismatch', {
          jobId: id,
          authenticatedShop: shopDomain,
          jobShop: existingJob.shopDomain,
        });
        return res.status(403).json({ 
          error: 'Access denied - job belongs to different shop',
          code: 'CROSS_TENANT_ACCESS_DENIED'
        });
      }

      const job = await bulkJobProcessor.cancelJob(id);
      
      res.json({
        job,
        message: 'Job cancelled successfully',
      });
    } catch (error) {
      logger.error('Failed to cancel job', {
        jobId: req.params.id,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      res.status(400).json({ 
        error: error instanceof Error ? error.message : 'Failed to cancel job',
      });
    }
  });

  // Export products
  app.post('/api/export', exportLimiter.middleware(), async (req, res) => {
    try {
      const schema = z.object({
        vendor: z.string().optional(),
        filters: z.object({
          status: z.string().optional(),
          productType: z.string().optional(),
        }).optional(),
      });

      const { vendor, filters } = schema.parse(req.body);
      // SECURITY FIX: Use authenticated shop domain from middleware
      const shopDomain = req.shopDomain!;

      logger.exportRequest(shopDomain, vendor, filters);

      const signedUrl = await csvExportService.exportProducts({
        shopDomain,
        vendor,
        filters,
      });

      res.json({
        downloadUrl: signedUrl,
        message: 'Export created successfully',
      });
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({
          error: 'Invalid request data',
          details: error.errors,
        });
      }

      logger.error('Export failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      res.status(500).json({ error: 'Failed to create export' });
    }
  });

  // Download exported CSV
  app.get('/api/export/download/:exportId', async (req, res) => {
    try {
      const { exportId } = req.params;
      const { token } = req.query;
      // SECURITY FIX: Use authenticated shop domain from middleware
      const shopDomain = req.shopDomain!;

      if (!token || typeof token !== 'string') {
        return res.status(400).json({ error: 'Missing export token' });
      }

      // Verify token
      const tokenData = csvExportService.verifyExportToken(token);
      
      // SECURITY FIX: Ensure the export belongs to the authenticated shop
      if (tokenData.shopDomain !== shopDomain) {
        logger.error('Export download - shop domain mismatch', {
          exportId,
          authenticatedShop: shopDomain,
          tokenShop: tokenData.shopDomain,
        });
        return res.status(403).json({ error: 'Access denied - export belongs to different shop' });
      }
      
      // Get CSV content
      const csvContent = await csvExportService.getCsvContent(exportId);
      
      if (!csvContent) {
        return res.status(404).json({ error: 'Export not found or expired' });
      }

      // Set headers for CSV download
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename="products-export-${exportId}.csv"`);
      res.send(csvContent);

      logger.info('CSV download completed', {
        exportId,
        shopDomain,
      });
    } catch (error) {
      logger.error('CSV download failed', {
        exportId: req.params.exportId,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      res.status(400).json({ error: 'Invalid or expired download link' });
    }
  });

  // Get shop settings
  app.get('/api/settings', async (req, res) => {
    try {
      // SECURITY FIX: Use authenticated shop domain from middleware
      const shopDomain = req.shopDomain!;

      const settings = await storage.getShopSettings(shopDomain);
      
      if (!settings) {
        return res.status(404).json({ error: 'Shop settings not found' });
      }

      // Return settings without sensitive data
      res.json({
        shopDomain: settings.shopDomain,
        showVendorColumn: settings.showVendorColumn,
        lastUpdated: settings.lastUpdated,
      });
    } catch (error) {
      logger.error('Failed to get settings', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      res.status(500).json({ error: 'Failed to fetch settings' });
    }
  });

  // Update shop settings
  app.post('/api/settings', async (req, res) => {
    try {
      const schema = z.object({
        showVendorColumn: z.boolean().optional(),
      });

      const { showVendorColumn } = schema.parse(req.body);
      // SECURITY FIX: Use authenticated shop domain from middleware
      const shopDomain = req.shopDomain!;

      const updatedSettings = await storage.updateShopSettings(shopDomain, {
        showVendorColumn,
      });

      res.json({
        shopDomain: updatedSettings.shopDomain,
        showVendorColumn: updatedSettings.showVendorColumn,
        lastUpdated: updatedSettings.lastUpdated,
      });
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({
          error: 'Invalid request data',
          details: error.errors,
        });
      }

      logger.error('Failed to update settings', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      res.status(500).json({ error: 'Failed to update settings' });
    }
  });

  // Get system statistics
  app.get('/api/stats', async (req, res) => {
    try {
      const stats = await storage.getSystemStats();
      const apiStats = await storage.getApiLogStats(24);
      
      res.json({
        ...stats,
        apiEndpoints: apiStats,
      });
    } catch (error) {
      logger.error('Failed to get system stats', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      res.status(500).json({ error: 'Failed to fetch system statistics' });
    }
  });

  // Get API logs
  app.get('/api/logs', async (req, res) => {
    try {
      const { limit } = req.query;
      // SECURITY FIX: Use authenticated shop domain from middleware
      const shopDomain = req.shopDomain!;
      
      const logs = await storage.getApiLogs(
        shopDomain,
        limit ? parseInt(limit as string) : undefined
      );

      res.json({ logs });
    } catch (error) {
      logger.error('Failed to get API logs', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      res.status(500).json({ error: 'Failed to fetch API logs' });
    }
  });


  const httpServer = createServer(app);
  return httpServer;
}
