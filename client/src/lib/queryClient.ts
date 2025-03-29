import { QueryClient, QueryFunction } from "@tanstack/react-query";

async function throwIfResNotOk(res: Response) {
  if (!res.ok) {
    const text = (await res.text()) || res.statusText;
    throw new Error(`${res.status}: ${text}`);
  }
}

// Store CSRF token
let csrfToken: string | null = null;
let csrfTokenPromise: Promise<string> | null = null;

// Fetch CSRF token if needed
async function getCsrfToken(): Promise<string> {
  // Return existing token if available
  if (csrfToken) return csrfToken;
  
  // Return existing promise if token is being fetched
  if (csrfTokenPromise) return csrfTokenPromise;
  
  // Create new promise to fetch token
  csrfTokenPromise = new Promise<string>(async (resolve, reject) => {
    try {
      console.log('Fetching new CSRF token');
      const response = await fetch('/api/csrf-token', {
        credentials: 'include',
      });
      
      if (!response.ok) {
        console.error(`Failed to fetch CSRF token: ${response.status} ${response.statusText}`);
        throw new Error(`Failed to fetch CSRF token: ${response.status}`);
      }
      
      const data = await response.json();
      if (!data.csrfToken) {
        console.error('No CSRF token returned from server');
        throw new Error('No CSRF token returned from server');
      }
      
      const token = data.csrfToken;
      csrfToken = token;
      console.log('Successfully retrieved CSRF token');
      resolve(token);
    } catch (error) {
      console.error('Error fetching CSRF token:', error);
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
  
  // Add CSRF token for state-changing requests
  if (method !== 'GET') {
    try {
      const token = await getCsrfToken();
      headers['CSRF-Token'] = token;
    } catch (error) {
      console.error('Could not add CSRF token to request', error);
      
      // Don't attempt to make the request without a CSRF token except for auth routes
      if (!url.includes('/api/auth/')) {
        throw new Error('CSRF token required but not available');
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
      retryCount < 1 && 
      method !== 'GET' && 
      !url.includes('/api/auth/')) {
    
    console.log('CSRF token rejected, fetching a new token and retrying...');
    // Reset the token so we'll fetch a new one
    csrfToken = null;
    csrfTokenPromise = null;
    
    // Retry the request with the new token
    return apiRequest(method, url, data, retryCount + 1);
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
