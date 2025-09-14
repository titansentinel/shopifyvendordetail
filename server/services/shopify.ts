import { logger } from '../utils/logger';

export interface ShopifyProduct {
  id: string;
  title: string;
  vendor: string;
  status: string;
  totalInventory: number;
  productType: string;
}

export interface ShopifyProductsResponse {
  products: {
    edges: Array<{
      cursor: string;
      node: ShopifyProduct;
    }>;
    pageInfo: {
      hasNextPage: boolean;
      endCursor: string;
    };
  };
}

export interface ShopifyProductUpdateResponse {
  productUpdate: {
    product?: {
      id: string;
      vendor: string;
    };
    userErrors: Array<{
      field: string;
      message: string;
    }>;
  };
}

export interface BulkUpdateResult {
  successCount: number;
  failureCount: number;
  errors: Array<{
    productId: string;
    error: string;
  }>;
  userErrors: Array<{
    productId: string;
    field: string;
    message: string;
  }>;
}

export class ShopifyService {
  private baseUrl: string;
  private accessToken: string;

  constructor(shopDomain: string, accessToken: string) {
    this.baseUrl = `https://${shopDomain}/admin/api/2023-10/graphql.json`;
    this.accessToken = accessToken;
  }

  private async makeGraphQLRequestWithRetry<T>(query: string, variables?: any, maxRetries = 3): Promise<T> {
    let lastError: Error | null = null;
    
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        return await this.makeGraphQLRequest<T>(query, variables);
      } catch (error) {
        lastError = error as Error;
        
        // Don't retry 4xx errors except 429
        if (error instanceof Error && error.message.includes('Shopify API error:')) {
          const statusMatch = error.message.match(/Shopify API error: (\d+)/);
          if (statusMatch) {
            const status = parseInt(statusMatch[1]);
            if (status >= 400 && status < 500 && status !== 429) {
              throw error; // Don't retry 4xx except 429
            }
          }
        }
        
        if (attempt === maxRetries) {
          break; // Final attempt failed
        }
        
        // Use Retry-After header for 429 errors, otherwise exponential backoff
        let delay: number;
        const retryAfter = (error as any).retryAfter;
        
        if (retryAfter && typeof retryAfter === 'number') {
          // Use API-specified retry delay for rate limit errors
          delay = retryAfter;
          logger.warn('Shopify API request failed (rate limited), using Retry-After delay', {
            attempt,
            maxRetries,
            error: error instanceof Error ? error.message : 'Unknown error',
            retryAfterMs: delay,
          });
        } else {
          // Exponential backoff with jitter for other errors
          const baseDelay = Math.pow(2, attempt - 1) * 1000; // 1s, 2s, 4s
          const jitter = Math.random() * 500; // 0-500ms jitter
          delay = baseDelay + jitter;
          logger.warn('Shopify API request failed, retrying with exponential backoff', {
            attempt,
            maxRetries,
            error: error instanceof Error ? error.message : 'Unknown error',
            retryDelay: delay,
          });
        }
        
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
    
    throw lastError || new Error('All retry attempts failed');
  }

  private async makeGraphQLRequest<T>(query: string, variables?: any): Promise<T> {
    const startTime = Date.now();
    
    try {
      const response = await fetch(this.baseUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Shopify-Access-Token': this.accessToken,
        },
        body: JSON.stringify({
          query,
          variables,
        }),
      });

      const responseTime = Date.now() - startTime;
      
      // Check rate limiting headers
      const callLimit = response.headers.get('X-Shopify-Shop-Api-Call-Limit');
      if (callLimit) {
        const [current, max] = callLimit.split('/').map(Number);
        if (current / max > 0.8) { // Over 80% of rate limit
          logger.warn('Approaching Shopify rate limit', {
            current,
            max,
            percentage: Math.round((current / max) * 100),
          });
        }
      }
      
      if (!response.ok) {
        const retryAfter = response.headers.get('Retry-After');
        logger.error('Shopify API error', {
          status: response.status,
          statusText: response.statusText,
          responseTime,
          retryAfter,
        });
        
        // Create error with retry-after information for 429 rate limit errors
        const error = new Error(`Shopify API error: ${response.status} ${response.statusText}`);
        if (response.status === 429 && retryAfter) {
          (error as any).retryAfter = parseInt(retryAfter, 10) * 1000; // Convert seconds to milliseconds
        }
        throw error;
      }

      const data = await response.json();
      
      if (data.errors) {
        logger.error('Shopify GraphQL errors', { errors: data.errors, responseTime });
        throw new Error(`GraphQL errors: ${JSON.stringify(data.errors)}`);
      }

      logger.info('Shopify API success', {
        endpoint: 'graphql',
        responseTime,
        callLimit,
      });

      return data.data as T;
    } catch (error) {
      const responseTime = Date.now() - startTime;
      logger.error('Shopify API request failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
        responseTime,
      });
      throw error;
    }
  }

  async getProducts(first = 50, after?: string, query?: string): Promise<ShopifyProductsResponse> {
    const graphqlQuery = `
      query GetProducts($first: Int!, $after: String, $query: String) {
        products(first: $first, after: $after, query: $query) {
          edges {
            cursor
            node {
              id
              title
              vendor
              status
              totalInventory
              productType
            }
          }
          pageInfo {
            hasNextPage
            endCursor
          }
        }
      }
    `;

    return this.makeGraphQLRequestWithRetry<ShopifyProductsResponse>(graphqlQuery, {
      first,
      after,
      query,
    });
  }

  async updateProductVendor(productId: string, vendor: string): Promise<ShopifyProductUpdateResponse> {
    const mutation = `
      mutation UpdateProductVendor($productId: ID!, $vendor: String!) {
        productUpdate(input: {id: $productId, vendor: $vendor}) {
          product {
            id
            vendor
          }
          userErrors {
            field
            message
          }
        }
      }
    `;

    return this.makeGraphQLRequestWithRetry<ShopifyProductUpdateResponse>(mutation, {
      productId,
      vendor,
    });
  }

  async bulkUpdateVendor(productIds: string[], vendor: string): Promise<BulkUpdateResult> {
    const result: BulkUpdateResult = {
      successCount: 0,
      failureCount: 0,
      errors: [],
      userErrors: [],
    };

    // Process products individually since Shopify doesn't have a bulk vendor update mutation
    for (const productId of productIds) {
      try {
        const response = await this.updateProductVendor(productId, vendor);
        
        if (response.productUpdate.userErrors.length > 0) {
          result.failureCount++;
          response.productUpdate.userErrors.forEach(error => {
            result.userErrors.push({
              productId,
              field: error.field,
              message: error.message,
            });
          });
          logger.warn('Product update had user errors', {
            productId,
            errors: response.productUpdate.userErrors,
          });
        } else {
          result.successCount++;
          logger.debug('Product vendor updated successfully', {
            productId,
            vendor,
          });
        }

        // Add delay between requests to respect rate limits
        if (productIds.indexOf(productId) < productIds.length - 1) {
          await new Promise(resolve => setTimeout(resolve, 250)); // 4 requests per second
        }

      } catch (error) {
        result.failureCount++;
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        result.errors.push({
          productId,
          error: errorMessage,
        });
        logger.error('Product update failed', {
          productId,
          error: errorMessage,
        });
      }
    }

    logger.info('Bulk vendor update completed', {
      totalProducts: productIds.length,
      successCount: result.successCount,
      failureCount: result.failureCount,
      vendor,
    });

    return result;
  }

  async getAllVendors(): Promise<string[]> {
    const vendors = new Set<string>();
    let hasNextPage = true;
    let cursor: string | undefined;

    while (hasNextPage) {
      const response = await this.getProducts(250, cursor);
      
      response.products.edges.forEach(edge => {
        if (edge.node.vendor) {
          vendors.add(edge.node.vendor);
        }
      });

      hasNextPage = response.products.pageInfo.hasNextPage;
      cursor = response.products.pageInfo.endCursor;
    }

    return Array.from(vendors).sort();
  }

  async getProductsByVendor(vendor: string): Promise<ShopifyProduct[]> {
    const products: ShopifyProduct[] = [];
    let hasNextPage = true;
    let cursor: string | undefined;

    while (hasNextPage) {
      const response = await this.getProducts(250, cursor, `vendor:"${vendor}"`);
      
      response.products.edges.forEach(edge => {
        products.push(edge.node);
      });

      hasNextPage = response.products.pageInfo.hasNextPage;
      cursor = response.products.pageInfo.endCursor;
    }

    return products;
  }

  async validateConnection(): Promise<boolean> {
    try {
      await this.getProducts(1);
      return true;
    } catch (error) {
      logger.error('Shopify connection validation failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      return false;
    }
  }
}

export function createShopifyService(shopDomain: string, accessToken: string): ShopifyService {
  return new ShopifyService(shopDomain, accessToken);
}
