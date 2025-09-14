import { QueryClient, QueryFunction } from "@tanstack/react-query";
import { addSessionToUrl } from "./session";

async function throwIfResNotOk(res: Response) {
  if (!res.ok) {
    const text = (await res.text()) || res.statusText;
    throw new Error(`${res.status}: ${text}`);
  }
}

// Get API base URL from environment variable or default to current origin  
const getApiBaseUrl = () => {
  return import.meta.env.VITE_API_URL || window.location.origin;
};

export async function apiRequest(
  method: string,
  url: string,
  data?: unknown | undefined,
): Promise<Response> {
  const baseUrl = getApiBaseUrl();
  let fullUrl = url.startsWith('/') ? `${baseUrl}${url}` : `${baseUrl}/${url}`;
  
  // Add session parameters to URL
  fullUrl = addSessionToUrl(fullUrl);
  
  const res = await fetch(fullUrl, {
    method,
    headers: data ? { "Content-Type": "application/json" } : {},
    body: data ? JSON.stringify(data) : undefined,
    credentials: "include",
  });

  await throwIfResNotOk(res);
  return res;
}

type UnauthorizedBehavior = "returnNull" | "throw";
export const getQueryFn: <T>(options: {
  on401: UnauthorizedBehavior;
}) => QueryFunction<T> =
  ({ on401: unauthorizedBehavior }) =>
  async ({ queryKey }) => {
    const baseUrl = getApiBaseUrl();
    let fullUrl = `${baseUrl}${queryKey.join("/")}`;
    
    // Add session parameters to URL
    fullUrl = addSessionToUrl(fullUrl);
    
    const res = await fetch(fullUrl, {
      credentials: "include",
    });

    if (unauthorizedBehavior === "returnNull" && res.status === 401) {
      return null;
    }

    await throwIfResNotOk(res);
    return await res.json();
  };

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      queryFn: getQueryFn({ on401: "throw" }),
      refetchInterval: false,
      refetchOnWindowFocus: false,
      staleTime: Infinity,
      retry: false,
    },
    mutations: {
      retry: false,
    },
  },
});
