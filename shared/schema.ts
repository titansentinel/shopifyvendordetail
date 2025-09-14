import { sql } from "drizzle-orm";
import { pgTable, text, varchar, timestamp, integer, boolean, jsonb } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";
import { relations } from "drizzle-orm";

export const users = pgTable("users", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  username: text("username").notNull().unique(),
  password: text("password").notNull(),
});

export const shopSettings = pgTable("shop_settings", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  shopDomain: text("shop_domain").notNull().unique(),
  showVendorColumn: boolean("show_vendor_column").default(true),
  accessToken: text("access_token"),
  encryptedToken: text("encrypted_token"),
  tokenScope: text("token_scope"),
  lastUpdated: timestamp("last_updated").defaultNow(),
  createdAt: timestamp("created_at").defaultNow(),
});

export const bulkJobs = pgTable("bulk_jobs", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  shopDomain: text("shop_domain").notNull(),
  productIds: jsonb("product_ids").$type<string[]>().notNull(),
  targetVendor: text("target_vendor").notNull(),
  status: text("status").$type<'PENDING' | 'RUNNING' | 'SUCCESS' | 'FAILED'>().default('PENDING'),
  errorMessage: text("error_message"),
  processedCount: integer("processed_count").default(0),
  totalCount: integer("total_count").notNull(),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
  completedAt: timestamp("completed_at"),
});

export const vendors = pgTable("vendors", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  shopDomain: text("shop_domain").notNull(),
  name: text("name").notNull(),
  productCount: integer("product_count").default(0),
  lastUpdated: timestamp("last_updated").defaultNow(),
});

export const apiLogs = pgTable("api_logs", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  shopDomain: text("shop_domain"),
  endpoint: text("endpoint").notNull(),
  method: text("method").notNull(),
  statusCode: integer("status_code"),
  responseTime: integer("response_time"),
  errorMessage: text("error_message"),
  timestamp: timestamp("timestamp").defaultNow(),
});

export const systemMetrics = pgTable("system_metrics", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  metricName: text("metric_name").notNull(),
  value: text("value").notNull(),
  timestamp: timestamp("timestamp").defaultNow(),
});

// Relations
export const shopSettingsRelations = relations(shopSettings, ({ many }) => ({
  bulkJobs: many(bulkJobs),
  vendors: many(vendors),
  apiLogs: many(apiLogs),
}));

export const bulkJobsRelations = relations(bulkJobs, ({ one }) => ({
  shop: one(shopSettings, {
    fields: [bulkJobs.shopDomain],
    references: [shopSettings.shopDomain],
  }),
}));

export const vendorsRelations = relations(vendors, ({ one }) => ({
  shop: one(shopSettings, {
    fields: [vendors.shopDomain],
    references: [shopSettings.shopDomain],
  }),
}));

export const apiLogsRelations = relations(apiLogs, ({ one }) => ({
  shop: one(shopSettings, {
    fields: [apiLogs.shopDomain],
    references: [shopSettings.shopDomain],
  }),
}));

// Insert schemas
export const insertUserSchema = createInsertSchema(users).pick({
  username: true,
  password: true,
});

export const insertShopSettingsSchema = createInsertSchema(shopSettings).omit({
  id: true,
  createdAt: true,
  lastUpdated: true,
});

export const insertBulkJobSchema = createInsertSchema(bulkJobs).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
  completedAt: true,
  processedCount: true,
});

export const insertVendorSchema = createInsertSchema(vendors).omit({
  id: true,
  lastUpdated: true,
});

export const insertApiLogSchema = createInsertSchema(apiLogs).omit({
  id: true,
  timestamp: true,
});

export const insertSystemMetricSchema = createInsertSchema(systemMetrics).omit({
  id: true,
  timestamp: true,
});

// Types
export type User = typeof users.$inferSelect;
export type InsertUser = z.infer<typeof insertUserSchema>;

export type ShopSettings = typeof shopSettings.$inferSelect;
export type InsertShopSettings = z.infer<typeof insertShopSettingsSchema>;

export type BulkJob = typeof bulkJobs.$inferSelect;
export type InsertBulkJob = z.infer<typeof insertBulkJobSchema>;

export type Vendor = typeof vendors.$inferSelect;
export type InsertVendor = z.infer<typeof insertVendorSchema>;

export type ApiLog = typeof apiLogs.$inferSelect;
export type InsertApiLog = z.infer<typeof insertApiLogSchema>;

export type SystemMetric = typeof systemMetrics.$inferSelect;
export type InsertSystemMetric = z.infer<typeof insertSystemMetricSchema>;
