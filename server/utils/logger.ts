interface LogLevel {
  ERROR: 'error';
  WARN: 'warn';
  INFO: 'info';
  DEBUG: 'debug';
}

const LOG_LEVELS: LogLevel = {
  ERROR: 'error',
  WARN: 'warn',
  INFO: 'info',
  DEBUG: 'debug',
};

interface LogEntry {
  timestamp: string;
  level: string;
  message: string;
  metadata?: any;
}

class Logger {
  private logLevel: string;

  constructor() {
    this.logLevel = process.env.LOG_LEVEL || 'info';
  }

  private shouldLog(level: string): boolean {
    const levels = ['error', 'warn', 'info', 'debug'];
    return levels.indexOf(level) <= levels.indexOf(this.logLevel);
  }

  private formatLog(level: string, message: string, metadata?: any): LogEntry {
    return {
      timestamp: new Date().toISOString(),
      level: level.toUpperCase(),
      message,
      ...(metadata && { metadata }),
    };
  }

  private output(logEntry: LogEntry): void {
    const logString = JSON.stringify(logEntry);
    
    if (logEntry.level === 'ERROR') {
      console.error(logString);
    } else if (logEntry.level === 'WARN') {
      console.warn(logString);
    } else {
      console.log(logString);
    }
  }

  error(message: string, metadata?: any): void {
    if (this.shouldLog(LOG_LEVELS.ERROR)) {
      this.output(this.formatLog(LOG_LEVELS.ERROR, message, metadata));
    }
  }

  warn(message: string, metadata?: any): void {
    if (this.shouldLog(LOG_LEVELS.WARN)) {
      this.output(this.formatLog(LOG_LEVELS.WARN, message, metadata));
    }
  }

  info(message: string, metadata?: any): void {
    if (this.shouldLog(LOG_LEVELS.INFO)) {
      this.output(this.formatLog(LOG_LEVELS.INFO, message, metadata));
    }
  }

  debug(message: string, metadata?: any): void {
    if (this.shouldLog(LOG_LEVELS.DEBUG)) {
      this.output(this.formatLog(LOG_LEVELS.DEBUG, message, metadata));
    }
  }

  // Specific methods for different types of logs
  apiCall(method: string, endpoint: string, statusCode: number, responseTime: number, metadata?: any): void {
    this.info('API Call', {
      method,
      endpoint,
      statusCode,
      responseTime,
      ...metadata,
    });
  }

  bulkJobStart(jobId: string, shopDomain: string, productCount: number): void {
    this.info('Bulk job started', {
      jobId,
      shopDomain,
      productCount,
      event: 'bulk_job_start',
    });
  }

  bulkJobComplete(jobId: string, processedCount: number, totalCount: number, duration: number): void {
    this.info('Bulk job completed', {
      jobId,
      processedCount,
      totalCount,
      duration,
      event: 'bulk_job_complete',
    });
  }

  bulkJobFailed(jobId: string, error: string, processedCount: number, totalCount: number): void {
    this.error('Bulk job failed', {
      jobId,
      error,
      processedCount,
      totalCount,
      event: 'bulk_job_failed',
    });
  }

  exportRequest(shopDomain: string, vendor?: string, filters?: any): void {
    this.info('Export requested', {
      shopDomain,
      vendor,
      filters,
      event: 'export_request',
    });
  }

  exportComplete(shopDomain: string, productCount: number, exportId: string): void {
    this.info('Export completed', {
      shopDomain,
      productCount,
      exportId,
      event: 'export_complete',
    });
  }

  shopifyApiError(shopDomain: string, endpoint: string, error: string, responseTime: number): void {
    this.error('Shopify API error', {
      shopDomain,
      endpoint,
      error,
      responseTime,
      event: 'shopify_api_error',
    });
  }

  shopifyRateLimit(shopDomain: string, retryAfter: number): void {
    this.warn('Shopify rate limit hit', {
      shopDomain,
      retryAfter,
      event: 'shopify_rate_limit',
    });
  }

  authSuccess(shopDomain: string, scope?: string): void {
    this.info('Shop authentication successful', {
      shopDomain,
      scope,
      event: 'auth_success',
    });
  }

  authFailure(shopDomain: string, error: string): void {
    this.error('Shop authentication failed', {
      shopDomain,
      error,
      event: 'auth_failure',
    });
  }

  cacheHit(key: string, type: string): void {
    this.debug('Cache hit', {
      key,
      type,
      event: 'cache_hit',
    });
  }

  cacheMiss(key: string, type: string): void {
    this.debug('Cache miss', {
      key,
      type,
      event: 'cache_miss',
    });
  }

  systemMetric(metricName: string, value: any, unit?: string): void {
    this.info('System metric', {
      metricName,
      value,
      unit,
      event: 'system_metric',
    });
  }
}

export const logger = new Logger();

// Helper function to measure execution time
export function measureTime<T>(
  operation: () => Promise<T>,
  operationName: string
): Promise<T> {
  const start = Date.now();
  
  return operation()
    .then(result => {
      const duration = Date.now() - start;
      logger.info(`Operation completed: ${operationName}`, { duration });
      return result;
    })
    .catch(error => {
      const duration = Date.now() - start;
      logger.error(`Operation failed: ${operationName}`, { 
        duration,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      throw error;
    });
}
