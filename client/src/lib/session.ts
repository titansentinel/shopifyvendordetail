/**
 * Session utility for handling shop authentication
 */

export interface SessionInfo {
    shop: string | null;
    session: string | null;
  }
  
  /**
   * Get session info from URL parameters
   */
  export function getSessionFromUrl(): SessionInfo {
    const urlParams = new URLSearchParams(window.location.search);
    return {
      shop: urlParams.get('shop'),
      session: urlParams.get('session'),
    };
  }
  
  /**
   * Get session parameters for API calls
   */
  export function getSessionParams(): string {
    const { shop, session } = getSessionFromUrl();
    
    if (!shop || !session) {
      return '';
    }
    
    return `shopDomain=${encodeURIComponent(shop)}&session=${encodeURIComponent(session)}`;
  }
  
  /**
   * Add session parameters to URL
   */
  export function addSessionToUrl(url: string): string {
    const sessionParams = getSessionParams();
    if (!sessionParams) return url;
    
    const separator = url.includes('?') ? '&' : '?';
    return `${url}${separator}${sessionParams}`;
  }
  
  /**
   * Check if user has valid session
   */
  export function hasValidSession(): boolean {
    const { shop, session } = getSessionFromUrl();
    return !!(shop && session);
  }