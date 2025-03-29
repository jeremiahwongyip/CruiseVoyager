import { createContext, ReactNode, useContext } from "react";
import {
  useQuery,
  useMutation,
  UseMutationResult,
} from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { useLocation } from "wouter";

// Define types
export type User = {
  id: number;
  username: string;
  email: string;
  firstName?: string | null;
  lastName?: string | null;
  [key: string]: any; // For additional properties
};

export type LoginCredentials = {
  username: string;
  password: string;
};

export type RegisterData = {
  username: string;
  email: string;
  password: string;
  confirmPassword: string;
  firstName?: string;
  lastName?: string;
};

type AuthContextType = {
  user: User | null;
  isLoading: boolean;
  error: Error | null;
  loginMutation: UseMutationResult<User, Error, LoginCredentials>;
  logoutMutation: UseMutationResult<void, Error, void>;
  registerMutation: UseMutationResult<User, Error, RegisterData>;
};

export const AuthContext = createContext<AuthContextType | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const { toast } = useToast();
  const [_, navigate] = useLocation();
  
  const {
    data: user,
    error,
    isLoading,
  } = useQuery<User | null, Error>({
    queryKey: ['/api/auth/user'],
    refetchOnWindowFocus: false,
    retry: false,
    select: (data: any) => data || null,
    staleTime: 1000 * 60 * 5, // 5 minutes
    // We'll handle errors with error boundaries or in the component
  });

  const loginMutation = useMutation({
    mutationFn: async (credentials: LoginCredentials) => {
      const res = await apiRequest('POST', '/api/auth/login', credentials);
      return await res.json();
    },
    onSuccess: () => {
      toast({
        title: "Login successful",
        description: "Welcome back!",
        variant: "success",
      });
      queryClient.invalidateQueries({ queryKey: ['/api/auth/user'] });
      navigate('/');
    },
    onError: (error: Error) => {
      toast({
        title: "Login failed",
        description: error.message || "Please check your credentials and try again.",
        variant: "destructive",
      });
    },
  });

  const registerMutation = useMutation({
    mutationFn: async (data: RegisterData) => {
      const res = await apiRequest('POST', '/api/auth/register', data);
      return await res.json();
    },
    onSuccess: () => {
      toast({
        title: "Registration successful",
        description: "Your account has been created successfully!",
        variant: "success",
      });
      queryClient.invalidateQueries({ queryKey: ['/api/auth/user'] });
      navigate('/');
    },
    onError: (error: Error) => {
      toast({
        title: "Registration failed",
        description: error.message || "There was an error creating your account.",
        variant: "destructive",
      });
    },
  });

  const logoutMutation = useMutation({
    mutationFn: async () => {
      await apiRequest('POST', '/api/auth/logout');
    },
    onSuccess: () => {
      queryClient.setQueryData(['/api/auth/user'], null);
      toast({
        title: "Logged out",
        description: "You have been successfully logged out.",
        variant: "success",
      });
      navigate('/');
    },
    onError: (error: Error) => {
      toast({
        title: "Logout failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  return (
    <AuthContext.Provider
      value={{
        user: user ?? null,
        isLoading,
        error,
        loginMutation,
        logoutMutation,
        registerMutation,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}