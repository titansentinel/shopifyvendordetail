import { 
  users, shopSettings, bulkJobs, vendors, apiLogs, systemMetrics,
  type User, type InsertUser,
  type ShopSettings, type InsertShopSettings,
  type BulkJob, type InsertBulkJob,
  type Vendor, type InsertVendor,
  type ApiLog, type InsertApiLog,
  type SystemMetric, type InsertSystemMetric
} from "@shared/schema";
import { db } from "./db";
import { eq, desc, and, gte, count, sql } from "drizzle-orm";

export interface IStorage {
  // User methods
  getUser(id: string): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;

  // Shop settings methods
  getShopSettings(shopDomain: string): Promise<ShopSettings | undefined>;
  createShopSettings(settings: InsertShopSettings): Promise<ShopSettings>;
  updateShopSettings(shopDomain: string, settings: Partial<InsertShopSettings>): Promise<ShopSettings>;

  // Bulk job methods
  createBulkJob(job: InsertBulkJob): Promise<BulkJob>;
  getBulkJob(id: string): Promise<BulkJob | undefined>;
  updateBulkJob(id: string, updates: Partial<BulkJob>): Promise<BulkJob>;
  getRecentBulkJobs(shopDomain?: string, limit?: number): Promise<BulkJob[]>;
  getBulkJobsByStatus(status: BulkJob['status']): Promise<BulkJob[]>;

  // Vendor methods
  getVendors(shopDomain: string): Promise<Vendor[]>;
  createVendor(vendor: InsertVendor): Promise<Vendor>;
  updateVendor(id: string, updates: Partial<Vendor>): Promise<Vendor>;
  deleteVendor(id: string): Promise<void>;
  getVendorByName(shopDomain: string, name: string): Promise<Vendor | undefined>;

  // API log methods
  createApiLog(log: InsertApiLog): Promise<ApiLog>;
  getApiLogs(shopDomain?: string, limit?: number): Promise<ApiLog[]>;
  getApiLogStats(hours?: number): Promise<{ endpoint: string; avgResponseTime: number; errorRate: number }[]>;

  // System metrics methods
  createSystemMetric(metric: InsertSystemMetric): Promise<SystemMetric>;
  getSystemMetrics(metricName?: string, hours?: number): Promise<SystemMetric[]>;
  getSystemStats(): Promise<{
    activeShops: number;
    totalVendors: number;
    bulkJobsToday: number;
    apiSuccessRate: number;
  }>;
}

export class DatabaseStorage implements IStorage {
  async getUser(id: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.id, id));
    return user || undefined;
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.username, username));
    return user || undefined;
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const [user] = await db
      .insert(users)
      .values(insertUser)
      .returning();
    return user;
  }

  async getShopSettings(shopDomain: string): Promise<ShopSettings | undefined> {
    const [settings] = await db
      .select()
      .from(shopSettings)
      .where(eq(shopSettings.shopDomain, shopDomain));
    return settings || undefined;
  }

  async createShopSettings(settings: InsertShopSettings): Promise<ShopSettings> {
    const [newSettings] = await db
      .insert(shopSettings)
      .values(settings)
      .returning();
    return newSettings;
  }

  async updateShopSettings(shopDomain: string, updates: Partial<InsertShopSettings>): Promise<ShopSettings> {
    const [updatedSettings] = await db
      .update(shopSettings)
      .set({ ...updates, lastUpdated: new Date() })
      .where(eq(shopSettings.shopDomain, shopDomain))
      .returning();
    return updatedSettings;
  }

  async createBulkJob(job: InsertBulkJob): Promise<BulkJob> {
    const jobData = {
      shopDomain: job.shopDomain,
      productIds: job.productIds,
      targetVendor: job.targetVendor,
      status: job.status || ('PENDING' as const),
      totalCount: job.productIds.length,
    };
    
    const [newJob] = await db
      .insert(bulkJobs)
      .values(jobData)
      .returning();
    return newJob;
  }

  async getBulkJob(id: string): Promise<BulkJob | undefined> {
    const [job] = await db
      .select()
      .from(bulkJobs)
      .where(eq(bulkJobs.id, id));
    return job || undefined;
  }

  async updateBulkJob(id: string, updates: Partial<BulkJob>): Promise<BulkJob> {
    const [updatedJob] = await db
      .update(bulkJobs)
      .set({ ...updates, updatedAt: new Date() })
      .where(eq(bulkJobs.id, id))
      .returning();
    return updatedJob;
  }

  async getRecentBulkJobs(shopDomain?: string, limit = 10): Promise<BulkJob[]> {
    if (shopDomain) {
      return await db
        .select()
        .from(bulkJobs)
        .where(eq(bulkJobs.shopDomain, shopDomain))
        .orderBy(desc(bulkJobs.createdAt))
        .limit(limit);
    }
    
    return await db
      .select()
      .from(bulkJobs)
      .orderBy(desc(bulkJobs.createdAt))
      .limit(limit);
  }

  async getBulkJobsByStatus(status: BulkJob['status']): Promise<BulkJob[]> {
    return await db
      .select()
      .from(bulkJobs)
      .where(eq(bulkJobs.status, status as any))
      .orderBy(desc(bulkJobs.createdAt));
  }

  async getVendors(shopDomain: string): Promise<Vendor[]> {
    return db
      .select()
      .from(vendors)
      .where(eq(vendors.shopDomain, shopDomain))
      .orderBy(vendors.name);
  }

  async createVendor(vendor: InsertVendor): Promise<Vendor> {
    const [newVendor] = await db
      .insert(vendors)
      .values(vendor)
      .returning();
    return newVendor;
  }

  async updateVendor(id: string, updates: Partial<Vendor>): Promise<Vendor> {
    const [updatedVendor] = await db
      .update(vendors)
      .set({ ...updates, lastUpdated: new Date() })
      .where(eq(vendors.id, id))
      .returning();
    return updatedVendor;
  }

  async deleteVendor(id: string): Promise<void> {
    await db.delete(vendors).where(eq(vendors.id, id));
  }

  async getVendorByName(shopDomain: string, name: string): Promise<Vendor | undefined> {
    const [vendor] = await db
      .select()
      .from(vendors)
      .where(and(eq(vendors.shopDomain, shopDomain), eq(vendors.name, name)));
    return vendor || undefined;
  }

  async createApiLog(log: InsertApiLog): Promise<ApiLog> {
    const [newLog] = await db
      .insert(apiLogs)
      .values(log)
      .returning();
    return newLog;
  }

  async getApiLogs(shopDomain?: string, limit = 100): Promise<ApiLog[]> {
    if (shopDomain) {
      return await db
        .select()
        .from(apiLogs)
        .where(eq(apiLogs.shopDomain, shopDomain))
        .orderBy(desc(apiLogs.timestamp))
        .limit(limit);
    }
    
    return await db
      .select()
      .from(apiLogs)
      .orderBy(desc(apiLogs.timestamp))
      .limit(limit);
  }

  async getApiLogStats(hours = 24): Promise<{ endpoint: string; avgResponseTime: number; errorRate: number }[]> {
    const since = new Date(Date.now() - hours * 60 * 60 * 1000);
    
    const stats = await db
      .select({
        endpoint: apiLogs.endpoint,
        avgResponseTime: sql<number>`AVG(${apiLogs.responseTime})::integer`,
        totalRequests: count(),
        errorCount: sql<number>`SUM(CASE WHEN ${apiLogs.statusCode} >= 400 THEN 1 ELSE 0 END)::integer`,
      })
      .from(apiLogs)
      .where(gte(apiLogs.timestamp, since))
      .groupBy(apiLogs.endpoint);

    return stats.map(stat => ({
      endpoint: stat.endpoint,
      avgResponseTime: stat.avgResponseTime || 0,
      errorRate: stat.totalRequests > 0 ? (stat.errorCount / stat.totalRequests) * 100 : 0,
    }));
  }

  async createSystemMetric(metric: InsertSystemMetric): Promise<SystemMetric> {
    const [newMetric] = await db
      .insert(systemMetrics)
      .values(metric)
      .returning();
    return newMetric;
  }

  async getSystemMetrics(metricName?: string, hours = 24): Promise<SystemMetric[]> {
    const since = new Date(Date.now() - hours * 60 * 60 * 1000);
    
    if (metricName) {
      return await db
        .select()
        .from(systemMetrics)
        .where(and(
          gte(systemMetrics.timestamp, since),
          eq(systemMetrics.metricName, metricName)
        ))
        .orderBy(desc(systemMetrics.timestamp));
    }
    
    return await db
      .select()
      .from(systemMetrics)
      .where(gte(systemMetrics.timestamp, since))
      .orderBy(desc(systemMetrics.timestamp));
  }

  async getSystemStats(): Promise<{
    activeShops: number;
    totalVendors: number;
    bulkJobsToday: number;
    apiSuccessRate: number;
  }> {
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    const [activeShopsResult] = await db
      .select({ count: count() })
      .from(shopSettings);

    const [totalVendorsResult] = await db
      .select({ count: count() })
      .from(vendors);

    const [bulkJobsTodayResult] = await db
      .select({ count: count() })
      .from(bulkJobs)
      .where(gte(bulkJobs.createdAt, today));

    const [apiStatsResult] = await db
      .select({
        total: count(),
        errors: sql<number>`SUM(CASE WHEN ${apiLogs.statusCode} >= 400 THEN 1 ELSE 0 END)::integer`,
      })
      .from(apiLogs)
      .where(gte(apiLogs.timestamp, today));

    const successRate = apiStatsResult.total > 0 
      ? ((apiStatsResult.total - apiStatsResult.errors) / apiStatsResult.total) * 100 
      : 100;

    return {
      activeShops: activeShopsResult.count,
      totalVendors: totalVendorsResult.count,
      bulkJobsToday: bulkJobsTodayResult.count,
      apiSuccessRate: Math.round(successRate * 10) / 10,
    };
  }
}

export const storage = new DatabaseStorage();
