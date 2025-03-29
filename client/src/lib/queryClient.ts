import { QueryClient, QueryFunction } from "@tanstack/react-query";

async function throwIfResNotOk(res: Response) {
  if (!res.ok) {
    const text = (await res.text()) || res.statusText;
    throw new Error(`${res.status}: ${text}`);
  }
}

// Store CSRF token
let csrfToken: string | null = null;

// Fetch CSRF token if needed
async function getCsrfToken(): Promise<string> {
  if (csrfToken) return csrfToken;
  
  try {
    const response = await fetch('/api/csrf-token', {
      credentials: 'include',
    });
    
    if (!response.ok) {
      throw new Error('Failed to fetch CSRF token');
    }
    
    const data = await response.json();
    csrfToken = data.csrfToken;
    return csrfToken || ''; // Return empty string if null for type safety
  } catch (error) {
    console.error('Error fetching CSRF token:', error);
    throw error;
  }
}

export async function apiRequest(
  method: string,
  url: string,
  data?: unknown | undefined,
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
      console.warn('Could not add CSRF token to request', error);
    }
  }
  
  const res = await fetch(url, {
    method,
    headers,
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
