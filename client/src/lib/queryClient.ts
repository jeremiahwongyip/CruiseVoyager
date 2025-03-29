import { QueryClient, QueryFunction } from "@tanstack/react-query";

async function throwIfResNotOk(res: Response) {
  if (!res.ok) {
    // Try to parse response as JSON first
    let errorMessage: string;
    try {
      const clone = res.clone();
      const json = await clone.json();
      errorMessage = json.message || JSON.stringify(json);
    } catch (e) {
      // If it's not valid JSON, get it as text
      const text = await res.text() || res.statusText;
      errorMessage = text;
    }
    
    // Create structured error based on status code
    switch (res.status) {
      case 401:
        console.error('[API] Authentication error:', errorMessage);
        throw new Error(`Authentication error: ${errorMessage}`);
      case 403:
        console.error('[API] Permission denied:', errorMessage);
        throw new Error(`Permission denied: ${errorMessage}`);
      case 404:
        console.error('[API] Not found:', errorMessage);
        throw new Error(`Not found: ${errorMessage}`);
      case 422:
        console.error('[API] Validation error:', errorMessage);
        throw new Error(`Validation error: ${errorMessage}`);
      case 429:
        console.error('[API] Rate limit exceeded:', errorMessage);
        throw new Error(`Rate limit exceeded: ${errorMessage}`);
      default:
        console.error(`[API] Error ${res.status}:`, errorMessage);
        throw new Error(`${res.status}: ${errorMessage}`);
    }
  }
}

// Store CSRF token
let csrfToken: string | null = null;
let csrfTokenPromise: Promise<string> | null = null;

// Fetch CSRF token if needed
async function getCsrfToken(forceRefresh = false): Promise<string> {
  // If force refresh, clear current token
  if (forceRefresh) {
    csrfToken = null;
    csrfTokenPromise = null;
  }
  
  // Return existing token if available
  if (csrfToken) return csrfToken;
  
  // Return existing promise if token is being fetched
  if (csrfTokenPromise) return csrfTokenPromise;
  
  // Create new promise to fetch token
  csrfTokenPromise = new Promise<string>(async (resolve, reject) => {
    try {
      console.log('[CSRF] Fetching new CSRF token');
      const response = await fetch('/api/csrf-token', {
        credentials: 'include',
        cache: 'no-store', // Don't cache this request
        headers: {
          'Pragma': 'no-cache',
          'Cache-Control': 'no-cache'
        }
      });
      
      if (!response.ok) {
        console.error(`[CSRF] Failed to fetch CSRF token: ${response.status} ${response.statusText}`);
        throw new Error(`Failed to fetch CSRF token: ${response.status}`);
      }
      
      const data = await response.json();
      if (!data.csrfToken) {
        console.error('[CSRF] No CSRF token returned from server');
        throw new Error('No CSRF token returned from server');
      }
      
      const token = data.csrfToken;
      csrfToken = token;
      console.log('[CSRF] Successfully retrieved CSRF token:', token.substring(0, 10) + '...');
      // Store the timestamp when we got the token
      window.localStorage.setItem('csrfTokenTimestamp', Date.now().toString());
      resolve(token);
    } catch (error) {
      console.error('[CSRF] Error fetching CSRF token:', error);
      // Reset promise so we can try again
      csrfTokenPromise = null;
      reject(error);
    }
  });
  
  return csrfTokenPromise;
}

export async function apiRequest(
  method: string,
  url: string,
  data?: unknown | undefined,
  retryCount = 0
): Promise<Response> {
  // Set up headers
  const headers: Record<string, string> = {};
  
  if (data) {
    headers['Content-Type'] = 'application/json';
  }
  
  // Check if the token might be too old (over 1 hour) and force refresh if needed
  const tokenTimestamp = window.localStorage.getItem('csrfTokenTimestamp');
  const tokenAge = tokenTimestamp ? Date.now() - parseInt(tokenTimestamp) : Infinity;
  const isTokenStale = tokenAge > 1000 * 60 * 60; // 1 hour
  
  // Add CSRF token for state-changing requests
  if (method !== 'GET') {
    try {
      // Force refresh token if it's stale
      const token = await getCsrfToken(isTokenStale);
      headers['CSRF-Token'] = token;
      
      console.log(`[API] ${method} ${url} with CSRF token: ${token.substring(0, 10)}...`);
    } catch (error) {
      console.error('[API] Could not add CSRF token to request', error);
      
      // Auth routes are exempted from CSRF
      if (!url.includes('/api/auth/login') && !url.includes('/api/auth/register')) {
        throw new Error('CSRF token required but not available');
      } else {
        console.log('[API] Proceeding without CSRF token for auth route:', url);
      }
    }
  }
  
  const res = await fetch(url, {
    method,
    headers,
    body: data ? JSON.stringify(data) : undefined,
    credentials: "include",
  });

  // If we get a CSRF error and haven't retried too many times,
  // invalidate token and retry once
  if (res.status === 403 && 
      retryCount < 2 && 
      method !== 'GET') {
    
    // Check if it's a CSRF error
    const responseText = await res.text();
    if (responseText.includes('csrf') || responseText.includes('CSRF')) {
      console.log('[API] CSRF token rejected, fetching a new token and retrying...');
      // Force refresh the token
      await getCsrfToken(true);
      
      // Retry the request with the new token
      return apiRequest(method, url, data, retryCount + 1);
    }
    
    // If it's not a CSRF error, throw the original error
    throw new Error(`${res.status}: ${responseText}`);
  }

  // For 403 errors that aren't CSRF related or we've exhausted retries
  if (res.status === 403) {
    const responseText = await res.text();
    console.error('[API] Forbidden error after retries:', responseText);
    throw new Error(`${res.status}: ${responseText}`);
  }

  await throwIfResNotOk(res);
  return res;
}

type UnauthorizedBehavior = "returnNull" | "throw";
export const getQueryFn: <T>(options: {
  on401: UnauthorizedBehavior;
}) => QueryFunction<T> =
  ({ on401: unauthorizedBehavior }) =>
  async ({ queryKey }) => {
    const res = await fetch(queryKey[0] as string, {
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
