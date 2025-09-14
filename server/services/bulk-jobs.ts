import { storage } from '../storage';
import { createShopifyService, type BulkUpdateResult } from './shopify';
import { logger } from '../utils/logger';
import type { BulkJob, InsertBulkJob } from '@shared/schema';

export class BulkJobProcessor {
  private processingJobs = new Set<string>();

  async createJob(jobData: InsertBulkJob): Promise<BulkJob> {
    const job = await storage.createBulkJob(jobData);
    
    // Start processing the job asynchronously
    this.processJob(job.id).catch(error => {
      logger.error('Job processing failed', {
        jobId: job.id,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    });

    return job;
  }

  async getJob(id: string): Promise<BulkJob | undefined> {
    return storage.getBulkJob(id);
  }

  async getJobStatus(id: string): Promise<{ 
    job: BulkJob | undefined; 
    progress: number; 
    isProcessing: boolean; 
  }> {
    const job = await storage.getBulkJob(id);
    const progress = job ? (job.processedCount || 0) / job.totalCount : 0;
    const isProcessing = this.processingJobs.has(id);

    return {
      job,
      progress: Math.round(progress * 100),
      isProcessing,
    };
  }

  private async processJob(jobId: string): Promise<void> {
    if (this.processingJobs.has(jobId)) {
      logger.warn('Job already being processed', { jobId });
      return;
    }

    this.processingJobs.add(jobId);

    try {
      const job = await storage.getBulkJob(jobId);
      if (!job) {
        throw new Error('Job not found');
      }

      logger.info('Starting job processing', {
        jobId,
        shopDomain: job.shopDomain,
        productCount: job.productIds.length,
        targetVendor: job.targetVendor,
      });

      // Update job status to RUNNING
      await storage.updateBulkJob(jobId, { status: 'RUNNING' });

      // Get shop settings to retrieve access token
      const shopSettings = await storage.getShopSettings(job.shopDomain);
      if (!shopSettings?.accessToken) {
        throw new Error('Shop access token not found');
      }

      const shopifyService = createShopifyService(job.shopDomain, shopSettings.accessToken);

      // Process products in batches to avoid rate limits
      const batchSize = 10; // Reduced batch size for individual API calls
      let processedCount = 0;
      let successCount = 0;
      let failureCount = 0;
      const allErrors: string[] = [];

      for (let i = 0; i < job.productIds.length; i += batchSize) {
        const batch = job.productIds.slice(i, i + batchSize);
        
        try {
          const result: BulkUpdateResult = await shopifyService.bulkUpdateVendor(batch, job.targetVendor);
          
          // Track actual successes and failures
          successCount += result.successCount;
          failureCount += result.failureCount;
          processedCount += batch.length;
          
          // Log detailed results for this batch
          logger.info('Batch processing completed', {
            jobId,
            batchNumber: Math.floor(i / batchSize) + 1,
            batchSize: batch.length,
            successCount: result.successCount,
            failureCount: result.failureCount,
            totalSuccessCount: successCount,
            totalFailureCount: failureCount,
          });
          
          // Log user errors if any
          if (result.userErrors.length > 0) {
            logger.warn('Batch update had user errors', {
              jobId,
              batchNumber: Math.floor(i / batchSize) + 1,
              userErrors: result.userErrors,
            });
            allErrors.push(...result.userErrors.map(ue => 
              `Product ${ue.productId}: ${ue.message} (field: ${ue.field})`
            ));
          }
          
          // Log API errors if any
          if (result.errors.length > 0) {
            logger.warn('Batch update had API errors', {
              jobId,
              batchNumber: Math.floor(i / batchSize) + 1,
              apiErrors: result.errors,
            });
            allErrors.push(...result.errors.map(e => 
              `Product ${e.productId}: ${e.error}`
            ));
          }
          
          // Update progress
          await storage.updateBulkJob(jobId, { 
            processedCount,
          });

        } catch (error) {
          logger.error('Batch processing completely failed', {
            jobId,
            batchNumber: Math.floor(i / batchSize) + 1,
            batchSize: batch.length,
            error: error instanceof Error ? error.message : 'Unknown error',
          });
          
          // Mark all products in this batch as failed
          failureCount += batch.length;
          processedCount += batch.length;
          allErrors.push(`Batch ${Math.floor(i / batchSize) + 1}: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
      }

      // Determine final job status based on results
      const finalStatus = failureCount === 0 ? 'SUCCESS' : 'FAILED'; // Any failures mark job as FAILED
      
      const errorMessage = allErrors.length > 0 ? 
        `${failureCount} products failed. Errors: ${allErrors.slice(0, 5).join('; ')}${allErrors.length > 5 ? '...' : ''}` : 
        null;

      await storage.updateBulkJob(jobId, {
        status: finalStatus,
        processedCount,
        errorMessage,
        completedAt: new Date(),
      });

      logger.info('Job processing completed', {
        jobId,
        status: finalStatus,
        totalCount: job.totalCount,
        processedCount,
        successCount,
        failureCount,
        hasErrors: allErrors.length > 0,
      });
      
      if (failureCount > 0) {
        logger.warn('Job completed with failures', {
          jobId,
          successRate: Math.round((successCount / job.totalCount) * 100),
          errorSummary: allErrors.slice(0, 10), // Log first 10 errors for debugging
        });
      }

    } catch (error) {
      logger.error('Job processing failed', {
        jobId,
        error: error instanceof Error ? error.message : 'Unknown error',
      });

      await storage.updateBulkJob(jobId, {
        status: 'FAILED',
        errorMessage: error instanceof Error ? error.message : 'Unknown error',
        completedAt: new Date(),
      });
    } finally {
      this.processingJobs.delete(jobId);
    }
  }

  async retryJob(jobId: string): Promise<BulkJob> {
    const job = await storage.getBulkJob(jobId);
    if (!job) {
      throw new Error('Job not found');
    }

    if (job.status === 'RUNNING') {
      throw new Error('Job is currently running');
    }

    // Reset job status and counters
    const updatedJob = await storage.updateBulkJob(jobId, {
      status: 'PENDING',
      processedCount: 0,
      errorMessage: null,
      completedAt: null,
    });

    // Start processing again
    this.processJob(jobId).catch(error => {
      logger.error('Job retry failed', {
        jobId,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    });

    return updatedJob;
  }

  async cancelJob(jobId: string): Promise<BulkJob> {
    const job = await storage.getBulkJob(jobId);
    if (!job) {
      throw new Error('Job not found');
    }

    if (job.status !== 'RUNNING' && job.status !== 'PENDING') {
      throw new Error('Job cannot be cancelled in current status');
    }

    // Remove from processing set
    this.processingJobs.delete(jobId);

    return storage.updateBulkJob(jobId, {
      status: 'FAILED',
      errorMessage: 'Job cancelled by user',
      completedAt: new Date(),
    });
  }

  async getRecentJobs(shopDomain?: string, limit = 10): Promise<BulkJob[]> {
    return storage.getRecentBulkJobs(shopDomain, limit);
  }

  async getPendingJobs(): Promise<BulkJob[]> {
    return storage.getBulkJobsByStatus('PENDING');
  }

  async getRunningJobs(): Promise<BulkJob[]> {
    return storage.getBulkJobsByStatus('RUNNING');
  }
}

export const bulkJobProcessor = new BulkJobProcessor();
