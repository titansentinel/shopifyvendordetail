import { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger';

interface RateLimitConfig {
  windowMs: number;
  maxRequests: number;
  message?: string;
  skipSuccessfulRequests?: boolean;
}

interface RequestLog {
  count: number;
  resetTime: number;
}

export class RateLimiter {
  private requests = new Map<string, RequestLog>();
  private config: RateLimitConfig;

  constructor(config: RateLimitConfig) {
    this.config = config;
    
    // Clean up old entries every 5 minutes
    setInterval(() => {
      this.cleanup();
    }, 5 * 60 * 1000);
  }

  middleware() {
    return (req: Request, res: Response, next: NextFunction) => {
      const key = this.generateKey(req);
      const now = Date.now();
      const windowStart = now - this.config.windowMs;

      let requestLog = this.requests.get(key);

      if (!requestLog || requestLog.resetTime <= now) {
        requestLog = {
          count: 0,
          resetTime: now + this.config.windowMs,
        };
        this.requests.set(key, requestLog);
      }

      requestLog.count++;

      if (requestLog.count > this.config.maxRequests) {
        logger.warn('Rate limit exceeded', {
          key,
          count: requestLog.count,
          limit: this.config.maxRequests,
          windowMs: this.config.windowMs,
        });

        res.status(429).json({
          error: this.config.message || 'Too many requests',
          retryAfter: Math.ceil((requestLog.resetTime - now) / 1000),
        });
        return;
      }

      // Add rate limit headers
      res.set({
        'X-RateLimit-Limit': this.config.maxRequests.toString(),
        'X-RateLimit-Remaining': Math.max(0, this.config.maxRequests - requestLog.count).toString(),
        'X-RateLimit-Reset': Math.ceil(requestLog.resetTime / 1000).toString(),
      });

      next();
    };
  }

  private generateKey(req: Request): string {
    // Use shop domain if available, otherwise fall back to IP
    const shopDomain = req.headers['x-shop-domain'] as string || req.body?.shopDomain;
    return shopDomain || req.ip || req.connection.remoteAddress || 'unknown';
  }

  private cleanup(): void {
    const now = Date.now();
    let cleanedCount = 0;

    this.requests.forEach((requestLog, key) => {
      if (requestLog.resetTime <= now) {
        this.requests.delete(key);
        cleanedCount++;
      }
    });

    if (cleanedCount > 0) {
      logger.debug('Rate limiter cleanup', { cleanedEntries: cleanedCount });
    }
  }
}

// Shopify API rate limit: 2 requests per second
export const shopifyApiLimiter = new RateLimiter({
  windowMs: 1000, // 1 second
  maxRequests: 2,
  message: 'Shopify API rate limit exceeded. Please wait before making another request.',
});

// General API rate limit: 100 requests per minute
export const generalApiLimiter = new RateLimiter({
  windowMs: 60 * 1000, // 1 minute
  maxRequests: 100,
  message: 'API rate limit exceeded. Please wait before making more requests.',
});

// Bulk operations rate limit: 5 requests per minute
export const bulkOperationLimiter = new RateLimiter({
  windowMs: 60 * 1000, // 1 minute
  maxRequests: 5,
  message: 'Bulk operation rate limit exceeded. Please wait before starting another bulk operation.',
});

// Export rate limit: 10 requests per hour
export const exportLimiter = new RateLimiter({
  windowMs: 60 * 60 * 1000, // 1 hour
  maxRequests: 10,
  message: 'Export rate limit exceeded. Please wait before requesting another export.',
});
