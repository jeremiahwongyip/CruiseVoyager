# Detailed Technical Design Specification Document: Cruise Booking Platform

## Document Information

**Project Name:** Cruise Booking E-Commerce Platform  
**Version:** 1.0  
**Date:** March 29, 2025  
**Author:** Technical Design Team  

## Table of Contents

1. [Introduction](#1-introduction)
2. [System Architecture](#2-system-architecture)
3. [Technology Stack](#3-technology-stack)
4. [Database Design](#4-database-design)
5. [Authentication System](#5-authentication-system)
6. [Security Implementation](#6-security-implementation)
7. [Frontend Architecture](#7-frontend-architecture)
8. [Backend Architecture](#8-backend-architecture)
9. [API Endpoints](#9-api-endpoints)
10. [Data Models](#10-data-models)
11. [Component Design](#11-component-design)
12. [Booking Flow](#12-booking-flow)
13. [Payment Processing](#13-payment-processing)
14. [Error Handling](#14-error-handling)
15. [Performance Considerations](#15-performance-considerations)
16. [Security Considerations](#16-security-considerations)
17. [Known Issues and Limitations](#17-known-issues-and-limitations)
18. [Future Enhancements](#18-future-enhancements)
19. [Conclusion](#19-conclusion)
20. [Appendices](#20-appendices)

## 1. Introduction

### 1.1 Purpose
This technical design specification document provides a comprehensive overview of the Cruise Booking E-Commerce Platform, including its architecture, components, data models, and integration points. The platform is designed to facilitate the browsing, booking, and management of cruise packages for customers while ensuring a secure and intuitive user experience.

### 1.2 Project Overview
The Cruise Booking Platform is a modern, responsive web application inspired by commercial cruise booking sites like Carnival.com. It enables users to:

- Browse available cruise destinations and packages
- Register for user accounts and manage their profiles
- Search for cruises with specific criteria (destination, dates, duration)
- Book cruise packages with different cabin types
- Process payments securely
- Manage and view booking history
- Submit and track enquiries
- Provide testimonials about their cruise experiences

### 1.3 System Goals
- Create an intuitive user experience with modern design elements
- Implement secure user authentication and authorization
- Provide comprehensive booking management capabilities
- Ensure data integrity throughout the booking process
- Maintain robust security standards

### 1.4 Design Principles
- Separation of concerns between frontend and backend
- Type safety throughout the application using TypeScript
- Robust validation of all user inputs
- Graceful error handling
- Secure by design

## 2. System Architecture

### 2.1 High-Level Architecture
The system follows a modern single-page application (SPA) architecture with the following components:

1. **Frontend**: React-based SPA built with TypeScript, TailwindCSS, and Shadcn UI components
2. **Backend**: Node.js Express server with RESTful API endpoints
3. **Database**: PostgreSQL database for persistent storage
4. **Authentication**: Session-based authentication with Passport.js
5. **State Management**: TanStack Query for server state management
6. **Routing**: Wouter for client-side routing

### 2.2 System Components Diagram

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│                 │     │                 │     │                 │
│  React Frontend │<───>│  Express Server │<───>│  PostgreSQL DB  │
│                 │     │                 │     │                 │
└─────────────────┘     └─────────────────┘     └─────────────────┘
        ↑                       ↑
        │                       │
┌─────────────────┐     ┌─────────────────┐
│                 │     │                 │
│  Authentication │     │  Payment Gateway│
│  (Passport.js)  │     │  (Stripe)       │
│                 │     │                 │
└─────────────────┘     └─────────────────┘
```

### 2.3 Component Interaction
The system follows a client-server model where:
1. Frontend components make API requests to the backend server.
2. Backend server processes requests, interacts with the database, and returns responses.
3. Authentication is handled through secure HTTP-only cookies and sessions.
4. External services like payment gateways are integrated through secure APIs.

## 3. Technology Stack

### 3.1 Frontend Technologies
- **Framework**: React with TypeScript
- **Build Tool**: Vite
- **Routing**: Wouter
- **State Management**: TanStack Query (React Query)
- **UI Components**: Shadcn UI library
- **Styling**: TailwindCSS
- **Form Handling**: React Hook Form with Zod validation
- **HTTP Client**: Fetch API wrapped with custom error handling
- **Icons**: Lucide React, React Icons

### 3.2 Backend Technologies
- **Runtime**: Node.js
- **Framework**: Express
- **Language**: TypeScript
- **Database ORM**: Drizzle ORM
- **Authentication**: Passport.js with local strategy
- **Session Management**: express-session with connect-pg-simple
- **Password Hashing**: bcrypt
- **Validation**: zod and drizzle-zod
- **CSRF Protection**: csurf
- **Rate Limiting**: express-rate-limit

### 3.3 Database
- **Database Engine**: PostgreSQL
- **Schema Management**: Drizzle ORM
- **Migrations**: Drizzle kit

### 3.4 Development Tools
- **Package Manager**: npm
- **Version Control**: Git
- **Code Quality**: TypeScript strict mode

## 4. Database Design

### 4.1 Schema Overview
The database schema is designed to support all features of the cruise booking platform, with tables for users, destinations, cruises, bookings, payments, and more.

### 4.2 Core Tables
The schema is defined using Drizzle ORM with the following core tables:

#### 4.2.1 Users Table
```typescript
export const users = pgTable("users", {
  id: serial("id").primaryKey(),
  username: text("username").notNull().unique(),
  email: text("email").notNull().unique(),
  password: text("password").notNull(),
  firstName: text("first_name"),
  lastName: text("last_name"),
  phone: text("phone"),
  address: text("address"),
  city: text("city"),
  state: text("state"),
  zipCode: text("zip_code"),
  country: text("country"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
  lastLogin: timestamp("last_login"),
  isVerified: boolean("is_verified").default(false),
  resetToken: text("reset_token"),
  resetTokenExpiry: timestamp("reset_token_expiry"),
});
```

#### 4.2.2 Destinations Table
```typescript
export const destinations = pgTable("destinations", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  description: text("description").notNull(),
  imageUrl: text("image_url").notNull(),
  priceFrom: integer("price_from").notNull(),
  rating: doublePrecision("rating").notNull(),
  cruiseCount: integer("cruise_count").notNull(),
  durationRange: text("duration_range").notNull(),
});
```

#### 4.2.3 Cruises Table
```typescript
export const cruises = pgTable("cruises", {
  id: serial("id").primaryKey(),
  title: text("title").notNull(),
  description: text("description").notNull(),
  destinationId: integer("destination_id").notNull(),
  imageUrl: text("image_url").notNull(),
  departureFrom: text("departure_from").notNull(),
  duration: integer("duration").notNull(),
  pricePerPerson: integer("price_per_person").notNull(),
  originalPrice: integer("original_price"),
  cabinType: text("cabin_type").notNull(),
  inclusions: text("inclusions").notNull(),
  isBestSeller: boolean("is_best_seller").default(false),
  isNewItinerary: boolean("is_new_itinerary").default(false),
  rating: doublePrecision("rating").notNull(),
  availablePackages: text("available_packages").array().notNull(),
  availableDates: date("available_dates").array(),
});
```

#### 4.2.4 Bookings Table
```typescript
export const bookings = pgTable("bookings", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").notNull(),
  cruiseId: integer("cruise_id").notNull(),
  cabinTypeId: integer("cabin_type_id"),
  bookingDate: timestamp("booking_date").defaultNow().notNull(),
  departureDate: date("departure_date").notNull(),
  returnDate: date("return_date").notNull(),
  totalPrice: integer("total_price").notNull(),
  numberOfGuests: integer("number_of_guests").notNull(),
  cabinType: text("cabin_type").notNull(),
  guestDetails: jsonb("guest_details").notNull(),
  status: bookingStatusEnum("status").notNull().default("pending"),
  statusHistory: jsonb("status_history"),
  paymentStatus: paymentStatusEnum("payment_status").default("pending"),
  specialRequests: text("special_requests"),
  bookingReference: text("booking_reference").notNull().unique(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
  cancellationDate: timestamp("cancellation_date"),
  cancellationReason: cancellationReasonEnum("cancellation_reason"),
  cancellationNotes: text("cancellation_notes"),
  refundAmount: integer("refund_amount"),
  refundDate: timestamp("refund_date"),
  checkedIn: boolean("checked_in").default(false),
  checkInDate: timestamp("check_in_date"),
  termsAccepted: boolean("terms_accepted").default(false).notNull(),
  lastNotificationSent: timestamp("last_notification_sent"),
});
```

#### 4.2.5 Payments Table
```typescript
export const payments = pgTable("payments", {
  id: serial("id").primaryKey(),
  bookingId: integer("booking_id").notNull(),
  amount: integer("amount").notNull(),
  currency: text("currency").default("USD").notNull(),
  status: paymentStatusEnum("status").notNull().default("pending"),
  paymentMethod: paymentMethodEnum("payment_method").notNull(),
  transactionId: text("transaction_id"),
  paymentIntentId: text("payment_intent_id"),
  paymentDate: timestamp("payment_date").defaultNow().notNull(),
  billingAddress: jsonb("billing_address"),
  cardLast4: text("card_last4"),
  expiryMonth: text("expiry_month"),
  expiryYear: text("expiry_year"),
  cardholderName: text("cardholder_name"),
  refundAmount: integer("refund_amount"),
  refundDate: timestamp("refund_date"),
  gatewayResponse: jsonb("gateway_response"),
});
```

### 4.3 Enum Types
The database uses several PostgreSQL enum types to ensure data consistency:

```typescript
export const bookingStatusEnum = pgEnum("booking_status", [
  "pending",      // Initial state when booking is created
  "confirmed",    // Payment received and booking confirmed
  "in_progress",  // The cruise has started 
  "completed",    // The cruise has ended
  "cancelled",    // Booking was cancelled by customer or company
  "refunded"      // Booking was cancelled and payment refunded
]);

export const enquiryStatusEnum = pgEnum("enquiry_status", [
  "submitted", 
  "in_review", 
  "responded", 
  "closed"
]);

export const cabinTypeEnum = pgEnum("cabin_type", [
  "Interior", 
  "Ocean View Stateroom", 
  "Balcony Stateroom", 
  "Suite"
]);

export const cancellationReasonEnum = pgEnum("cancellation_reason", [
  "customer_request",
  "schedule_change",
  "medical",
  "weather",
  "emergency",
  "policy_violation",
  "other"
]);

export const paymentStatusEnum = pgEnum("payment_status", [
  "pending",      // Payment initiated but not completed
  "processing",   // Payment being processed by payment gateway
  "completed",    // Payment successfully completed
  "failed",       // Payment attempt failed
  "refunded",     // Payment was refunded
  "partially_refunded" // Payment was partially refunded
]);

export const paymentMethodEnum = pgEnum("payment_method", [
  "credit_card",
  "debit_card",
  "paypal",
  "bank_transfer",
  "stripe",
  "apple_pay",
  "google_pay"
]);
```

### 4.4 Table Relationships
Table relationships are explicitly defined using Drizzle ORM's relations API:

```typescript
export const usersRelations = relations(users, ({ many }) => ({
  bookings: many(bookings),
  enquiries: many(enquiries),
}));

export const destinationsRelations = relations(destinations, ({ many }) => ({
  cruises: many(cruises),
}));

export const cruisesRelations = relations(cruises, ({ one, many }) => ({
  destination: one(destinations, {
    fields: [cruises.destinationId],
    references: [destinations.id],
  }),
  bookings: many(bookings),
}));

export const bookingsRelations = relations(bookings, ({ one, many }) => ({
  user: one(users, {
    fields: [bookings.userId],
    references: [users.id],
  }),
  cruise: one(cruises, {
    fields: [bookings.cruiseId],
    references: [cruises.id],
  }),
  cabinType: one(cabinTypes, {
    fields: [bookings.cabinTypeId],
    references: [cabinTypes.id],
  }),
  payments: many(payments),
}));
```

### 4.5 Database Storage Interface
The application uses the Repository pattern through the `IStorage` interface to abstract database operations:

```typescript
export interface IStorage {
  // User methods
  getUser(id: number): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  getUserByEmail(email: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  updateUser(id: number, userData: Partial<InsertUser>): Promise<User | undefined>;
  updateUserPassword(id: number, password: string): Promise<User | undefined>;
  updateUserLastLogin(id: number): Promise<User | undefined>;
  createPasswordResetToken(email: string): Promise<string | undefined>;
  resetPassword(token: string, password: string): Promise<boolean>;
  
  // Destination methods
  getDestinations(): Promise<Destination[]>;
  getDestination(id: number): Promise<Destination | undefined>;
  createDestination(destination: InsertDestination): Promise<Destination>;
  
  // Cruise methods
  getCruises(): Promise<Cruise[]>;
  getCruise(id: number): Promise<Cruise | undefined>;
  getCruisesByDestination(destinationId: number): Promise<Cruise[]>;
  createCruise(cruise: InsertCruise): Promise<Cruise>;
  searchCruises(params: any): Promise<Cruise[]>;

  // Cabin Types methods
  getCabinTypes(cruiseId: number): Promise<CabinType[]>;
  getCabinType(id: number): Promise<CabinType | undefined>;
  createCabinType(cabinType: InsertCabinType): Promise<CabinType>;

  // Booking methods
  getBookings(userId: number): Promise<Booking[]>;
  getBooking(id: number): Promise<Booking | undefined>;
  getBookingByReference(reference: string): Promise<Booking | undefined>;
  createBooking(booking: InsertBooking): Promise<Booking>;
  updateBookingStatus(id: number, status: string): Promise<Booking | undefined>;
  cancelBooking(id: number, reason: string, cancellationReason?: string): Promise<Booking | undefined>;
  updateBookingStatusHistory(id: number, status: string): Promise<Booking | undefined>;
  processRefund(bookingId: number, amount: number): Promise<Booking | undefined>;
  checkInPassengers(bookingId: number): Promise<Booking | undefined>;
  getUpcomingBookings(userId: number): Promise<Booking[]>;
  getPastBookings(userId: number): Promise<Booking[]>;
  
  // Payment methods
  getPayments(bookingId: number): Promise<Payment[]>;
  getPayment(id: number): Promise<Payment | undefined>;
  createPayment(payment: InsertPayment): Promise<Payment>;
  updatePaymentStatus(id: number, status: string): Promise<Payment | undefined>;
  processStripePayment(bookingId: number, paymentData: any): Promise<Payment | undefined>;
  refundPayment(id: number, amount: number): Promise<Payment | undefined>;
  getPaymentsByStatus(status: string): Promise<Payment[]>;
  
  // Amenity methods
  getAmenities(): Promise<Amenity[]>;
  getAmenity(id: number): Promise<Amenity | undefined>;
  createAmenity(amenity: InsertAmenity): Promise<Amenity>;
  
  // Testimonial methods
  getTestimonials(): Promise<Testimonial[]>;
  getTestimonialsByCruise(cruiseId: number): Promise<Testimonial[]>;
  getTestimonial(id: number): Promise<Testimonial | undefined>;
  createTestimonial(testimonial: InsertTestimonial): Promise<Testimonial>;
  verifyTestimonial(id: number): Promise<Testimonial | undefined>;

  // Enquiry methods (Contact Us)
  getEnquiries(): Promise<Enquiry[]>;
  getEnquiriesByUser(userId: number): Promise<Enquiry[]>;
  getEnquiry(id: number): Promise<Enquiry | undefined>;
  createEnquiry(enquiry: InsertEnquiry): Promise<Enquiry>;
  updateEnquiryStatus(id: number, status: string): Promise<Enquiry | undefined>;
  assignEnquiry(id: number, userId: number): Promise<Enquiry | undefined>;
  
  // Enquiry Response methods
  getEnquiryResponses(enquiryId: number): Promise<EnquiryResponse[]>;
  createEnquiryResponse(response: InsertEnquiryResponse): Promise<EnquiryResponse>;
}
```

## 5. Authentication System

### 5.1 Authentication Flow
The authentication system uses Passport.js with a local strategy for username/password authentication. The process follows these steps:

1. User submits credentials via login or registration form
2. Server validates credentials
3. If valid, a session is created and stored in the database
4. A session cookie is sent to the client
5. Subsequent requests include this cookie for authentication

### 5.2 Passport Configuration
```typescript
// Configure local strategy
passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const user = await storage.getUserByUsername(username);
      if (!user) {
        return done(null, false, { message: "Invalid username" });
      }

      const isMatch = await comparePasswords(password, user.password);
      if (!isMatch) {
        return done(null, false, { message: "Invalid password" });
      }

      // Update last login timestamp
      await storage.updateUserLastLogin(user.id);
      return done(null, user);
    } catch (error) {
      return done(error);
    }
  })
);

// Serialize and deserialize user
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id: number, done) => {
  try {
    const user = await storage.getUser(id);
    done(null, user);
  } catch (error) {
    done(error);
  }
});
```

### 5.3 Session Management
Sessions are stored in the PostgreSQL database using connect-pg-simple:

```typescript
app.use(
  session({
    store: new PgSession({
      pool,
      tableName: "session", // Default table name
      createTableIfMissing: true,
    }),
    secret: APP_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
      secure: process.env.NODE_ENV === "production",
      httpOnly: true, // Prevents client-side JavaScript from reading the cookie
      sameSite: 'lax', // Provides some CSRF protection
    },
  })
);
```

### 5.4 Password Management
Passwords are securely hashed using bcrypt:

```typescript
export async function hashPassword(password: string): Promise<string> {
  const salt = await bcrypt.genSalt(10);
  return await bcrypt.hash(password, salt);
}

export async function comparePasswords(
  plainPassword: string,
  hashedPassword: string
): Promise<boolean> {
  return await bcrypt.compare(plainPassword, hashedPassword);
}
```

### 5.5 User Authentication Hooks
Client-side authentication is managed through a custom React hook that provides a consistent interface for auth-related operations:

```typescript
export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}

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

  // ... other mutations omitted for brevity

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
```

### 5.6 Protected Routes
The application uses a `ProtectedRoute` component to restrict access to authenticated users:

```typescript
export function ProtectedRoute({
  path,
  component: Component,
}: ProtectedRouteProps) {
  const { user, isLoading } = useAuth();

  return (
    <Route
      path={path}
      component={() => {
        if (isLoading) {
          return (
            <div className="flex items-center justify-center min-h-screen">
              <Loader2 className="h-8 w-8 animate-spin text-[#1a75bc]" />
            </div>
          );
        }

        if (!user) {
          return <Redirect to="/login" />;
        }

        return <Component />;
      }}
    />
  );
}
```

## 6. Security Implementation

### 6.1 CSRF Protection
The application implements Cross-Site Request Forgery (CSRF) protection using the csurf middleware:

```typescript
// CSRF protection
const csrfProtection = csrf({ cookie: true });

// Apply CSRF protection to all state-changing routes
// excluding login and register endpoints which would need the token first
app.use((req, res, next) => {
  // Skip CSRF check for login, register, and non-state-changing methods
  if (
    req.path === '/api/auth/login' ||
    req.path === '/api/auth/register' ||
    req.method === 'GET'
  ) {
    return next();
  }
  return csrfProtection(req, res, next);
});

// Provide CSRF token
app.get('/api/csrf-token', csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});
```

Client-side requests include the CSRF token for all state-changing operations:

```typescript
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
  if (method !== 'GET' && url !== '/api/auth/login' && url !== '/api/auth/register') {
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
```

### 6.2 Rate Limiting
The application implements rate limiting to prevent brute force attacks:

```typescript
// Rate limiting for authentication endpoints
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  limit: 5, // 5 failed attempts per IP per 15 minutes
  standardHeaders: true,
  legacyHeaders: false,
  message: { 
    message: 'Too many login attempts, please try again later'
  }
});

// Rate limiting for password reset
const resetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  limit: 3, // 3 attempts per IP per hour
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    message: 'Too many password reset attempts, please try again later'
  }
});

app.post("/api/auth/login", loginLimiter, (req: Request, res: Response, next: NextFunction) => {
  // Login logic
});

app.post("/api/auth/reset-request", resetLimiter, async (req: Request, res: Response) => {
  // Password reset request logic
});

app.post("/api/auth/reset-password", resetLimiter, async (req: Request, res: Response) => {
  // Password reset logic
});
```

### 6.3 Password Security
The application implements several measures for password security:

1. **Secure Hashing**: Passwords are hashed using bcrypt with a salt
2. **Minimum Length Requirements**: Password validation enforces minimum length
3. **Password Reset Functionality**: Secure token-based password reset flow

```typescript
// Password reset request
app.post("/api/auth/reset-request", resetLimiter, async (req: Request, res: Response) => {
  try {
    const { email } = req.body;
    const token = await storage.createPasswordResetToken(email);
    
    if (!token) {
      return res.status(404).json({ message: "Email not found" });
    }
    
    // In a real app, you would send an email with the reset link
    // For now, we'll just return the token in the response
    res.json({ 
      message: "Password reset token generated", 
      token, 
      resetLink: `/reset-password?token=${token}` 
    });
  } catch (error) {
    console.error("Password reset request error:", error);
    res.status(500).json({ message: "Error processing password reset request" });
  }
});
```

### 6.4 Authentication Guards
The application implements middleware to protect routes that require authentication:

```typescript
// Middleware to check if user is authenticated
app.use("/api/profile", (req: Request, res: Response, next: NextFunction) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ message: "Not authenticated" });
  }
  next();
});

// Middleware to check if user is authenticated
export function isAuthenticated(req: Request, res: Response, next: NextFunction) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.status(401).json({ message: "Not authenticated" });
}
```

### 6.5 Secure Cookies
The application uses secure, HTTP-only cookies for session management:

```typescript
// Session setup
app.use(
  session({
    // ... other settings
    cookie: {
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
      secure: process.env.NODE_ENV === "production", // Only sends over HTTPS in production
      httpOnly: true, // Prevents client-side JavaScript from reading the cookie
      sameSite: 'lax', // Provides some CSRF protection
    },
  })
);
```

### 6.6 Input Validation
All user inputs are validated both on the client and server side using Zod schemas:

```typescript
// Login schema
export const loginSchema = z.object({
  username: z.string().min(1, "Username is required"),
  password: z.string().min(1, "Password is required"),
});

// Registration schema with additional validation
export const registerSchema = insertUserSchema.extend({
  password: z.string().min(8, "Password must be at least 8 characters"),
  confirmPassword: z.string(),
}).refine(data => data.password === data.confirmPassword, {
  message: "Passwords don't match",
  path: ["confirmPassword"],
});

// Example of endpoint using validation
app.post("/api/cruises/search", async (req, res, next) => {
  try {
    // Validate input
    const searchParams = searchSchema.parse(req.body);
    
    const cruises = await storage.searchCruises(searchParams);
    res.json(cruises);
  } catch (error) {
    if (error instanceof ZodError) {
      return res.status(400).json({ message: fromZodError(error).message });
    }
    next(error);
  }
});
```

## 7. Frontend Architecture

### 7.1 Component Structure
The frontend follows a well-organized structure with the following key directories:

- `/client/src/components`: Reusable UI components
- `/client/src/hooks`: Custom React hooks
- `/client/src/lib`: Utility functions and services
- `/client/src/pages`: Page components corresponding to routes

### 7.2 Routing System
The application uses Wouter for client-side routing:

```typescript
function Router() {
  const [location] = useLocation();
  
  // Scroll to top on route changes
  useEffect(() => {
    window.scrollTo(0, 0);
  }, [location]);

  return (
    <div className="flex flex-col min-h-screen">
      <Navbar />
      <main className="flex-grow">
        <Switch>
          <Route path="/" component={Home} />
          <Route path="/auth" component={AuthPage} />
          <ProtectedRoute path="/profile" component={Profile} />
          <Route path="/destinations" component={Destinations} />
          <Route path="/cruise/:id" component={CruiseDetails} />
          <ProtectedRoute path="/booking/:cruiseId" component={Booking} />
          <Route path="/contact" component={Contact} />
          {/* Redirect legacy URLs to new auth page */}
          <Route path="/login">
            {() => {
              window.location.href = "/auth";
              return null;
            }}
          </Route>
          <Route path="/register">
            {() => {
              window.location.href = "/auth";
              return null;
            }}
          </Route>
          <Route component={NotFound} />
        </Switch>
      </main>
      <Footer />
    </div>
  );
}
```

### 7.3 State Management
The application uses TanStack Query (React Query) for server state management. This provides a consistent pattern for data fetching, caching, and updates:

```typescript
// Example of a query hook using TanStack Query
const {
  data: destinations,
  isLoading,
  error,
} = useQuery<Destination[]>({
  queryKey: ['/api/destinations'],
  staleTime: 5 * 60 * 1000, // 5 minutes
});

// Example of a mutation using TanStack Query
const bookingMutation = useMutation({
  mutationFn: async (bookingData: BookingData) => {
    const res = await apiRequest('POST', '/api/bookings', bookingData);
    return await res.json();
  },
  onSuccess: () => {
    toast({
      title: "Booking successful",
      description: "Your cruise booking has been confirmed!",
      variant: "success",
    });
    queryClient.invalidateQueries({ queryKey: ['/api/bookings'] });
    navigate('/profile');
  },
  onError: (error: Error) => {
    toast({
      title: "Booking failed",
      description: error.message,
      variant: "destructive",
    });
  },
});
```

### 7.4 UI Component Library
The application uses the Shadcn UI component library with TailwindCSS for consistent styling:

```tsx
// Example of a UI component using Shadcn
<Dialog>
  <DialogTrigger asChild>
    <Button variant="outline">View Details</Button>
  </DialogTrigger>
  <DialogContent className="sm:max-w-[425px]">
    <DialogHeader>
      <DialogTitle>Cruise Details</DialogTitle>
      <DialogDescription>
        View detailed information about this cruise.
      </DialogDescription>
    </DialogHeader>
    <div className="grid gap-4 py-4">
      {/* Content here */}
    </div>
    <DialogFooter>
      <Button type="button" onClick={handleClose}>
        Close
      </Button>
    </DialogFooter>
  </DialogContent>
</Dialog>
```

### 7.5 Form Handling
Forms are implemented using React Hook Form with Zod validation:

```tsx
// Example of form handling with React Hook Form and Zod
const form = useForm<LoginFormData>({
  resolver: zodResolver(loginSchema),
  defaultValues: {
    username: "",
    password: "",
  },
});

const onSubmit = (data: LoginFormData) => {
  loginMutation.mutate(data);
};

return (
  <Form {...form}>
    <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
      <FormField
        control={form.control}
        name="username"
        render={({ field }) => (
          <FormItem>
            <FormLabel>Username</FormLabel>
            <FormControl>
              <Input placeholder="Enter your username" {...field} />
            </FormControl>
            <FormMessage />
          </FormItem>
        )}
      />
      {/* Other form fields */}
      <Button type="submit" className="w-full" disabled={loginMutation.isPending}>
        {loginMutation.isPending ? (
          <Loader2 className="w-4 h-4 mr-2 animate-spin" />
        ) : null}
        Login
      </Button>
    </form>
  </Form>
);
```

## 8. Backend Architecture

### 8.1 Server Structure
The Express server is organized into several key files:

- `server/index.ts`: Entry point that configures the Express app
- `server/routes.ts`: API route definitions
- `server/auth.ts`: Authentication configuration and routes
- `server/storage.ts`: Data storage interface and implementation
- `server/db.ts`: Database connection and configuration

### 8.2 Middleware Stack
The server uses a middleware stack for various concerns:

```typescript
// Body parsing middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Cookie parser middleware (required for CSRF)
app.use(cookieParser());

// Session middleware
app.use(
  session({
    // Session configuration
  })
);

// Passport middleware
app.use(passport.initialize());
app.use(passport.session());

// CSRF protection middleware
app.use((req, res, next) => {
  // CSRF configuration
});

// Rate limiting middleware
const loginLimiter = rateLimit({
  // Rate limiting configuration
});
```

### 8.3 Route Organization
Routes are organized by resource and follow RESTful conventions:

```typescript
// Destination Routes
app.get("/api/destinations", async (_req, res, next) => {
  // List all destinations
});

app.get("/api/destinations/:id", async (req, res, next) => {
  // Get a specific destination
});

// Cruise Routes
app.get("/api/cruises", async (_req, res, next) => {
  // List all cruises
});

app.get("/api/cruises/:id", async (req, res, next) => {
  // Get a specific cruise
});

app.get("/api/cruises/destination/:destinationId", async (req, res, next) => {
  // List cruises for a specific destination
});

// Booking Routes
app.get("/api/bookings", async (req, res, next) => {
  // List user's bookings (requires authentication)
});

app.post("/api/bookings", async (req, res, next) => {
  // Create a new booking (requires authentication)
});
```

### 8.4 Error Handling
The server implements consistent error handling:

```typescript
// Global error handler
app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
  console.error(err);
  
  res.status(err.status || 500).json({
    message: err.message || "Internal Server Error",
  });
});

// Route-level error handling
app.get("/api/destinations", async (_req, res, next) => {
  try {
    const destinations = await storage.getDestinations();
    res.json(destinations);
  } catch (error) {
    next(error); // Pass to global error handler
  }
});

// Validation error handling
app.post("/api/cruises/search", async (req, res, next) => {
  try {
    // Validate input
    const searchParams = searchSchema.parse(req.body);
    
    const cruises = await storage.searchCruises(searchParams);
    res.json(cruises);
  } catch (error) {
    if (error instanceof ZodError) {
      return res.status(400).json({ message: fromZodError(error).message });
    }
    next(error);
  }
});
```

## 9. API Endpoints

### 9.1 Authentication Endpoints

| Endpoint | Method | Description | Authentication |
|----------|--------|-------------|----------------|
| `/api/auth/register` | POST | Register a new user | None |
| `/api/auth/login` | POST | Authenticate a user | None |
| `/api/auth/logout` | POST | Log out a user | Required |
| `/api/auth/user` | GET | Get current user information | Required |
| `/api/auth/reset-request` | POST | Request a password reset | None |
| `/api/auth/reset-password` | POST | Reset a password using a token | None |

### 9.2 Profile Endpoints

| Endpoint | Method | Description | Authentication |
|----------|--------|-------------|----------------|
| `/api/profile` | PATCH | Update user profile | Required |
| `/api/profile/change-password` | POST | Change user password | Required |

### 9.3 Destination Endpoints

| Endpoint | Method | Description | Authentication |
|----------|--------|-------------|----------------|
| `/api/destinations` | GET | List all destinations | None |
| `/api/destinations/:id` | GET | Get a specific destination | None |

### 9.4 Cruise Endpoints

| Endpoint | Method | Description | Authentication |
|----------|--------|-------------|----------------|
| `/api/cruises` | GET | List all cruises | None |
| `/api/cruises/:id` | GET | Get a specific cruise | None |
| `/api/cruises/destination/:destinationId` | GET | List cruises for a destination | None |
| `/api/cruises/search` | POST | Search for cruises with criteria | None |

### 9.5 Booking Endpoints

| Endpoint | Method | Description | Authentication |
|----------|--------|-------------|----------------|
| `/api/bookings` | GET | List user's bookings | Required |
| `/api/bookings/:id` | GET | Get a specific booking | Required |
| `/api/bookings` | POST | Create a new booking | Required |
| `/api/bookings/:id/status` | PATCH | Update booking status | Required |

### 9.6 Other Endpoints

| Endpoint | Method | Description | Authentication |
|----------|--------|-------------|----------------|
| `/api/amenities` | GET | List all amenities | None |
| `/api/testimonials` | GET | List all testimonials | None |
| `/api/testimonials` | POST | Create a new testimonial | Optional |
| `/api/contact` | POST | Submit a contact form | Optional |
| `/api/csrf-token` | GET | Get a CSRF token | None |

## 10. Data Models

### 10.1 Core Data Models
The application defines TypeScript types for all data models:

```typescript
export type User = typeof users.$inferSelect;
export type Destination = typeof destinations.$inferSelect;
export type Cruise = typeof cruises.$inferSelect;
export type Booking = typeof bookings.$inferSelect;
export type Amenity = typeof amenities.$inferSelect;
export type Testimonial = typeof testimonials.$inferSelect;
export type Enquiry = typeof enquiries.$inferSelect;
export type EnquiryResponse = typeof enquiryResponses.$inferSelect;
export type CabinType = typeof cabinTypes.$inferSelect;
export type Payment = typeof payments.$inferSelect;
```

### 10.2 Input Data Models
The application defines TypeScript types for all input models:

```typescript
export type InsertUser = z.infer<typeof insertUserSchema>;
export type InsertDestination = z.infer<typeof insertDestinationSchema>;
export type InsertCruise = z.infer<typeof insertCruiseSchema>;
export type InsertBooking = z.infer<typeof insertBookingSchema>;
export type InsertAmenity = z.infer<typeof insertAmenitySchema>;
export type InsertTestimonial = z.infer<typeof insertTestimonialSchema>;
export type InsertEnquiry = z.infer<typeof insertEnquirySchema>;
export type InsertEnquiryResponse = z.infer<typeof insertEnquiryResponseSchema>;
export type InsertCabinType = z.infer<typeof insertCabinTypeSchema>;
export type InsertPayment = z.infer<typeof insertPaymentSchema>;
```

### 10.3 Form Data Models
The application defines TypeScript types for form data:

```typescript
export type LoginCredentials = z.infer<typeof loginSchema>;
export type RegisterData = z.infer<typeof registerSchema>;
export type SearchData = z.infer<typeof searchSchema>;
export type ContactData = z.infer<typeof contactSchema>;
export type PasswordResetRequestData = z.infer<typeof passwordResetRequestSchema>;
export type PasswordResetData = z.infer<typeof passwordResetSchema>;
export type PaymentData = z.infer<typeof paymentSchema>;
export type BookingCancellationData = z.infer<typeof bookingCancellationSchema>;
```

## 11. Component Design

### 11.1 Navigation Components
The application implements a responsive navigation bar:

```tsx
function Navbar() {
  const { user, logoutMutation } = useAuth();

  return (
    <header className="sticky top-0 z-50 w-full border-b bg-background shadow-sm">
      <div className="container flex h-16 items-center">
        <Link href="/" className="flex items-center gap-2">
          <ShipIcon className="h-6 w-6 text-[#1a75bc]" />
          <span className="font-bold text-xl">Ocean Voyages</span>
        </Link>
        <nav className="hidden md:flex items-center ml-auto gap-6">
          <Link href="/" className="text-sm font-medium">
            Home
          </Link>
          <Link href="/destinations" className="text-sm font-medium">
            Destinations
          </Link>
          <Link href="/contact" className="text-sm font-medium">
            Contact
          </Link>
          {user ? (
            <>
              <Link href="/profile" className="text-sm font-medium">
                My Profile
              </Link>
              <Button
                variant="outline"
                size="sm"
                onClick={() => logoutMutation.mutate()}
                disabled={logoutMutation.isPending}
              >
                {logoutMutation.isPending ? (
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                ) : null}
                Logout
              </Button>
            </>
          ) : (
            <Link href="/auth">
              <Button size="sm">Login / Register</Button>
            </Link>
          )}
        </nav>
        <Sheet>
          <SheetTrigger asChild className="md:hidden ml-auto">
            <Button variant="outline" size="icon">
              <Menu className="h-5 w-5" />
            </Button>
          </SheetTrigger>
          <SheetContent>
            <SheetHeader>
              <SheetTitle>Ocean Voyages</SheetTitle>
            </SheetHeader>
            <nav className="flex flex-col gap-4 mt-4">
              {/* Mobile navigation links */}
            </nav>
          </SheetContent>
        </Sheet>
      </div>
    </header>
  );
}
```

### 11.2 Form Components
The application implements several form components for user interaction:

```tsx
// Login form component
function LoginForm() {
  const { loginMutation } = useAuth();
  const form = useForm<LoginCredentials>({
    resolver: zodResolver(loginSchema),
    defaultValues: {
      username: "",
      password: "",
    },
  });

  function onSubmit(values: LoginCredentials) {
    loginMutation.mutate(values);
  }

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
        <FormField
          control={form.control}
          name="username"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Username</FormLabel>
              <FormControl>
                <Input placeholder="Enter your username" {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="password"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Password</FormLabel>
              <FormControl>
                <Input 
                  type="password" 
                  placeholder="Enter your password" 
                  {...field} 
                />
              </FormControl>
              <FormMessage />
              <div className="text-sm">
                <Link href="/reset-password" className="text-[#1a75bc] hover:underline">
                  Forgot password?
                </Link>
              </div>
            </FormItem>
          )}
        />
        <Button 
          type="submit" 
          className="w-full" 
          disabled={loginMutation.isPending}
        >
          {loginMutation.isPending ? (
            <Loader2 className="h-4 w-4 mr-2 animate-spin" />
          ) : null}
          Login
        </Button>
      </form>
    </Form>
  );
}
```

### 11.3 Card Components
The application implements card components for displaying cruise and destination information:

```tsx
function CruiseCard({ cruise }: { cruise: Cruise }) {
  return (
    <Card className="overflow-hidden transition-all hover:shadow-md">
      <div className="relative">
        <AspectRatio ratio={16 / 9}>
          <img 
            src={cruise.imageUrl} 
            alt={cruise.title} 
            className="object-cover w-full h-full" 
          />
        </AspectRatio>
        {cruise.isBestSeller && (
          <Badge 
            className="absolute top-2 right-2 bg-[#ff7043]" 
            variant="secondary"
          >
            Best Seller
          </Badge>
        )}
        {cruise.isNewItinerary && (
          <Badge 
            className="absolute top-2 left-2 bg-[#1a75bc]" 
            variant="secondary"
          >
            New Itinerary
          </Badge>
        )}
      </div>
      <CardContent className="p-4">
        <div className="mb-2 flex items-center justify-between">
          <h3 className="font-semibold text-lg">{cruise.title}</h3>
          <div className="flex items-center">
            <Star className="h-4 w-4 fill-yellow-400 text-yellow-400" />
            <span className="ml-1 text-sm">{cruise.rating}</span>
          </div>
        </div>
        <div className="flex flex-col gap-1 text-sm text-muted-foreground">
          <div className="flex items-center">
            <MapPin className="h-4 w-4 mr-1" />
            <span>{cruise.departureFrom}</span>
          </div>
          <div className="flex items-center">
            <Calendar className="h-4 w-4 mr-1" />
            <span>{cruise.duration} days</span>
          </div>
        </div>
        <div className="mt-4 flex items-center justify-between">
          <div>
            <p className="text-xs text-muted-foreground">From</p>
            <p className="font-semibold text-lg">${cruise.pricePerPerson}</p>
            {cruise.originalPrice && (
              <p className="text-xs line-through text-muted-foreground">
                ${cruise.originalPrice}
              </p>
            )}
          </div>
          <Link href={`/cruise/${cruise.id}`}>
            <Button size="sm">View Details</Button>
          </Link>
        </div>
      </CardContent>
    </Card>
  );
}
```

## 12. Booking Flow

### 12.1 Booking Process Overview
The booking process follows these steps:

1. User browses cruises and selects one
2. User views cruise details and selects "Book Now"
3. User is directed to booking form (must be authenticated)
4. User fills in booking details (dates, cabin type, guests)
5. User reviews booking summary
6. User provides payment details
7. Booking is confirmed and user receives confirmation

### 12.2 Booking Form
The booking form collects necessary information:

```tsx
function BookingForm({ cruise }: { cruise: Cruise }) {
  const { user } = useAuth();
  const { toast } = useToast();
  const [_, navigate] = useLocation();
  
  const form = useForm<BookingFormData>({
    resolver: zodResolver(bookingFormSchema),
    defaultValues: {
      cruiseId: cruise.id,
      departureDate: "",
      cabinType: "Interior",
      numberOfGuests: 2,
      guestDetails: [],
      specialRequests: "",
      termsAccepted: false
    }
  });

  const bookingMutation = useMutation({
    mutationFn: async (data: BookingFormData) => {
      const res = await apiRequest("POST", "/api/bookings", data);
      return await res.json();
    },
    onSuccess: (data) => {
      toast({
        title: "Booking Successful",
        description: `Your booking reference is ${data.booking.bookingReference}`,
        variant: "success"
      });
      navigate(`/booking/confirmation/${data.booking.id}`);
    },
    onError: (error: Error) => {
      toast({
        title: "Booking Failed",
        description: error.message,
        variant: "destructive"
      });
    }
  });

  function onSubmit(data: BookingFormData) {
    // Submit booking data
    bookingMutation.mutate(data);
  }

  // Return form JSX
}
```

### 12.3 Booking Confirmation
Once a booking is confirmed, the user receives a confirmation page:

```tsx
function BookingConfirmation({ bookingId }: { bookingId: string }) {
  const { data: booking, isLoading, error } = useQuery<Booking>({
    queryKey: [`/api/bookings/${bookingId}`],
  });

  if (isLoading) {
    return <LoadingSpinner />;
  }

  if (error || !booking) {
    return <ErrorDisplay error={error} />;
  }

  return (
    <div className="container py-8">
      <div className="max-w-3xl mx-auto">
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle>Booking Confirmation</CardTitle>
                <CardDescription>
                  Thank you for your booking with Ocean Voyages
                </CardDescription>
              </div>
              <CheckCircle className="h-12 w-12 text-green-500" />
            </div>
          </CardHeader>
          <CardContent>
            <div className="space-y-6">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <h3 className="font-medium text-sm text-muted-foreground">
                    Booking Reference
                  </h3>
                  <p className="font-bold">{booking.bookingReference}</p>
                </div>
                <div>
                  <h3 className="font-medium text-sm text-muted-foreground">
                    Booking Date
                  </h3>
                  <p>
                    {new Date(booking.bookingDate).toLocaleDateString()}
                  </p>
                </div>
                {/* Other booking details */}
              </div>
              
              <Separator />
              
              <div>
                <h3 className="font-semibold mb-2">Payment Summary</h3>
                <div className="flex justify-between">
                  <span>Total Amount</span>
                  <span className="font-bold">
                    ${(booking.totalPrice / 100).toFixed(2)}
                  </span>
                </div>
                <div className="flex justify-between text-sm text-muted-foreground">
                  <span>Payment Status</span>
                  <span className="capitalize">{booking.paymentStatus}</span>
                </div>
              </div>
            </div>
          </CardContent>
          <CardFooter className="flex justify-between">
            <Button 
              variant="outline" 
              onClick={() => window.print()}
              leftIcon={<Printer className="h-4 w-4 mr-2" />}
            >
              Print Receipt
            </Button>
            <Link href="/profile">
              <Button>View My Bookings</Button>
            </Link>
          </CardFooter>
        </Card>
      </div>
    </div>
  );
}
```

### 12.4 Booking Management
Users can manage their bookings from the profile page:

```tsx
function BookingManagement() {
  const { data: bookings, isLoading } = useQuery<Booking[]>({
    queryKey: ['/api/bookings'],
  });

  const tabs = [
    { id: "upcoming", label: "Upcoming" },
    { id: "past", label: "Past" },
    { id: "cancelled", label: "Cancelled" }
  ];

  const [activeTab, setActiveTab] = useState("upcoming");

  if (isLoading) {
    return <LoadingSpinner />;
  }

  const filteredBookings = bookings?.filter(booking => {
    if (activeTab === "cancelled") {
      return booking.status === "cancelled" || booking.status === "refunded";
    } else if (activeTab === "past") {
      return booking.status === "completed" && 
             booking.status !== "cancelled" && 
             booking.status !== "refunded";
    } else {
      return (booking.status === "pending" || 
             booking.status === "confirmed" || 
             booking.status === "in_progress") && 
             booking.status !== "cancelled" && 
             booking.status !== "refunded";
    }
  });

  return (
    <div>
      <h2 className="text-2xl font-bold mb-4">My Bookings</h2>
      
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          {tabs.map(tab => (
            <TabsTrigger key={tab.id} value={tab.id}>
              {tab.label}
            </TabsTrigger>
          ))}
        </TabsList>
        
        <TabsContent value={activeTab} className="mt-4">
          {filteredBookings?.length === 0 ? (
            <EmptyState 
              title={`No ${activeTab} bookings`} 
              description="When you book a cruise, it will appear here."
              icon={<Calendar className="h-16 w-16 text-muted-foreground opacity-20" />}
            />
          ) : (
            <div className="space-y-4">
              {filteredBookings?.map(booking => (
                <BookingCard key={booking.id} booking={booking} />
              ))}
            </div>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}
```

## 13. Payment Processing

### 13.1 Payment Integration
The application is designed to integrate with Stripe for payment processing. This integration would include:

1. Creating payment intents on the server
2. Using Stripe Elements for secure card collection
3. Processing payments and handling successful/failed transactions

### 13.2 Payment Flow
The payment flow would follow these steps:

1. User submits booking information
2. Server creates a payment intent with Stripe
3. Client displays Stripe Elements for secure card entry
4. User enters payment details
5. Payment is processed
6. Server updates booking status based on payment result

### 13.3 Refund Processing
The application includes functionality for refund processing:

```typescript
// Refund endpoint (server-side)
app.post("/api/bookings/:id/refund", async (req, res, next) => {
  try {
    const id = parseInt(req.params.id);
    if (isNaN(id)) {
      return res.status(400).json({ message: "Invalid booking ID" });
    }
    
    const { amount, reason } = req.body;
    
    // Process refund
    const booking = await storage.processRefund(id, amount);
    if (!booking) {
      return res.status(404).json({ message: "Booking not found" });
    }
    
    res.json({
      message: "Refund processed successfully",
      booking
    });
  } catch (error) {
    next(error);
  }
});
```

## 14. Error Handling

### 14.1 Frontend Error Handling
The frontend implements several layers of error handling:

1. Form validation errors using Zod and React Hook Form
2. Network request errors in API calls
3. Error states in components

```tsx
// Form validation error handling
const form = useForm<LoginCredentials>({
  resolver: zodResolver(loginSchema),
  defaultValues: {
    username: "",
    password: "",
  },
});

// API error handling
const loginMutation = useMutation({
  mutationFn: async (credentials: LoginCredentials) => {
    const res = await apiRequest('POST', '/api/auth/login', credentials);
    return await res.json();
  },
  onError: (error: Error) => {
    toast({
      title: "Login failed",
      description: error.message || "Please check your credentials and try again.",
      variant: "destructive",
    });
  },
});

// Component error handling
function CruiseDetails({ id }: { id: string }) {
  const { data, error, isLoading } = useQuery<Cruise>({
    queryKey: [`/api/cruises/${id}`],
  });

  if (isLoading) {
    return <LoadingSpinner />;
  }

  if (error) {
    return (
      <div className="container py-12">
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Error</AlertTitle>
          <AlertDescription>
            {error.message || "Failed to load cruise details"}
          </AlertDescription>
        </Alert>
      </div>
    );
  }

  // Render component
}
```

### 14.2 Backend Error Handling
The backend implements consistent error handling:

1. Route-level try/catch blocks
2. Global error handler middleware
3. Validation error handling

```typescript
// Route-level error handling
app.get("/api/cruises/:id", async (req, res, next) => {
  try {
    const id = parseInt(req.params.id);
    if (isNaN(id)) {
      return res.status(400).json({ message: "Invalid cruise ID" });
    }
    
    const cruise = await storage.getCruise(id);
    if (!cruise) {
      return res.status(404).json({ message: "Cruise not found" });
    }
    
    res.json(cruise);
  } catch (error) {
    next(error);
  }
});

// Global error handler
app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
  console.error(err);
  
  res.status(err.status || 500).json({
    message: err.message || "Internal Server Error",
  });
});
```

### 14.3 Error Logging
The application implements error logging throughout:

```typescript
// Backend error logging
app.post("/api/auth/register", async (req: Request, res: Response) => {
  try {
    // Registration logic
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ message: "Error registering user" });
  }
});

// Frontend error logging
loginMutation.onError = (error: Error) => {
  console.error("Login error:", error);
  toast({
    title: "Login failed",
    description: error.message,
    variant: "destructive",
  });
};
```

## 15. Performance Considerations

### 15.1 Query Caching
The application uses TanStack Query's caching capabilities to minimize unnecessary network requests:

```typescript
// Configure query defaults
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

// Example of query with custom staleTime
const { data: destinations } = useQuery<Destination[]>({
  queryKey: ['/api/destinations'],
  staleTime: 5 * 60 * 1000, // 5 minutes
});
```

### 15.2 Server-Side Optimizations
The server implements several optimizations:

1. Connection pooling for database queries
2. Efficient query patterns using Drizzle ORM
3. Minimal data transfer by selecting only required fields

### 15.3 Frontend Optimizations
The frontend implements several optimizations:

1. Lazy loading of components using React.lazy
2. Optimized rendering using memoization
3. Efficient state updates using TanStack Query

## 16. Security Considerations

### 16.1 Authentication Security
The authentication system implements several security features:

1. Secure password hashing with bcrypt
2. HTTP-only cookies for session storage
3. CSRF protection for all state-changing requests
4. Rate limiting for login and password reset attempts

### 16.2 Input Validation
All user inputs are thoroughly validated:

1. Client-side validation using Zod and React Hook Form
2. Server-side validation using Zod
3. Parameter sanitization for URL parameters

### 16.3 Data Protection
The application implements data protection measures:

1. Sensitive data is never exposed to the client
2. Passwords are securely hashed
3. All requests from authenticated users are properly authorized

## 17. Known Issues and Limitations

### 17.1 Technical Debt

1. **In-Memory Storage Limitation**: The current implementation uses an in-memory storage option which is not suitable for production use as data will be lost on server restart.

2. **Incomplete Error Handling**: Some edge cases may not be properly handled, particularly around payment processing and session expiration.

3. **Authentication Improvements**: The current authentication system could be enhanced with features like multi-factor authentication and better session management.

4. **Missing Email Integration**: Password reset and booking confirmation emails are currently mocked and would need to be implemented with a real email service.

5. **Limited Mobile Responsiveness**: While the application is designed with responsive principles, some components may not be fully optimized for all mobile devices.

### 17.2 Security Considerations

1. **Password Policies**: The system currently only enforces a minimum length for passwords but could benefit from more comprehensive password policies.

2. **Session Timeout**: There is no explicit session timeout or renewal mechanism implemented.

3. **Rate Limiting Coverage**: Rate limiting is only implemented for authentication endpoints but could be extended to other sensitive endpoints.

### 17.3 Performance Limitations

1. **Query Optimization**: Some database queries could be optimized for better performance, particularly those involving multiple tables.

2. **Asset Optimization**: Image assets are not optimized for different device sizes and network conditions.

3. **SSR/SSG Integration**: The application could benefit from server-side rendering or static site generation for improved initial load times.

## 18. Future Enhancements

### 18.1 Feature Enhancements

1. **Multi-Factor Authentication**: Implement additional security with MFA options.

2. **Social Login Integration**: Add options for login with Google, Facebook, and other social providers.

3. **Advanced Search and Filtering**: Enhance the cruise search with more advanced filtering options.

4. **User Reviews and Ratings**: Allow authenticated users to leave reviews and ratings for cruises they have booked.

5. **Wishlist Functionality**: Allow users to save cruises to a wishlist for future reference.

6. **Booking Modifications**: Enable users to modify their bookings within certain constraints.

7. **Loyalty Program**: Implement a loyalty points system for repeat customers.

### 18.2 Technical Improvements

1. **Email Service Integration**: Implement real email notifications for bookings, password resets, etc.

2. **Payment Gateway Integration**: Complete the Stripe integration for real payment processing.

3. **Internationalization**: Add support for multiple languages.

4. **Accessibility Improvements**: Enhance compliance with WCAG guidelines.

5. **Progressive Web App Features**: Add offline support and installability.

6. **Analytics Integration**: Add support for tracking user interactions and conversions.

7. **CI/CD Pipeline**: Implement automated testing and deployment.

## 19. Conclusion

The Cruise Booking Platform provides a comprehensive solution for users to browse, book, and manage cruise vacations. The application follows modern web development best practices with a focus on security, user experience, and maintainability.

The platform's modular architecture allows for easy extension and customization. The separation of concerns between the frontend and backend, along with the use of TypeScript throughout, ensures type safety and reduces the potential for bugs.

While there are some known limitations and areas for improvement, the current implementation provides a solid foundation for a production-ready application. Future enhancements can build upon this foundation to add more features and improve the overall user experience.

## 20. Appendices

### 20.1 Tech Stack Summary

- **Frontend**: React, TypeScript, TailwindCSS, Shadcn UI, TanStack Query, React Hook Form, Zod
- **Backend**: Node.js, Express, TypeScript, Passport.js, Drizzle ORM
- **Database**: PostgreSQL
- **Authentication**: Session-based with Passport.js
- **Form Validation**: Zod, React Hook Form
- **State Management**: TanStack Query
- **Styling**: TailwindCSS, Shadcn UI

### 20.2 Environment Variables

The application requires the following environment variables:

- `DATABASE_URL`: PostgreSQL connection string
- `APP_SECRET`: Secret for session encryption
- `NODE_ENV`: Environment (development, production)
- `PORT`: Server port
- `STRIPE_SECRET_KEY`: Stripe API secret key
- `VITE_STRIPE_PUBLIC_KEY`: Stripe API public key

### 20.3 Installation and Setup

To install and run the application:

1. Clone the repository
2. Install dependencies: `npm install`
3. Set up environment variables
4. Push database schema: `npm run db:push`
5. Start the development server: `npm run dev`

### 20.4 Project Structure

```
/
├── client/
│   ├── src/
│   │   ├── components/  # Reusable UI components
│   │   ├── hooks/       # Custom React hooks
│   │   ├── lib/         # Utility functions
│   │   ├── pages/       # Page components
│   │   ├── App.tsx      # Main application component
│   │   ├── index.css    # Global styles
│   │   └── main.tsx     # Application entry point
├── server/
│   ├── auth.ts          # Authentication configuration
│   ├── config.ts        # Server configuration
│   ├── db.ts            # Database connection
│   ├── index.ts         # Server entry point
│   ├── routes.ts        # API routes
│   ├── storage.ts       # Data storage interface
│   └── vite.ts          # Vite server integration
├── shared/
│   └── schema.ts        # Shared data schemas
└── package.json         # Project dependencies and scripts
```