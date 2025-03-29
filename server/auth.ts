import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Express, Request, Response, NextFunction } from "express";
import session from "express-session";
import connectPgSimple from "connect-pg-simple";
import bcrypt from "bcrypt";
import { storage } from "./storage";
import { User as UserType, LoginCredentials, RegisterData } from "@shared/schema";
import { pool } from "./db";
import { APP_SECRET } from "./config";
import csrf from "csurf";
import cookieParser from "cookie-parser";
import rateLimit from "express-rate-limit";

declare global {
  namespace Express {
    interface User extends UserType {}
  }
}

const PgSession = connectPgSimple(session);

// Function to hash password
export async function hashPassword(password: string): Promise<string> {
  const salt = await bcrypt.genSalt(10);
  return await bcrypt.hash(password, salt);
}

// Function to compare password with hashed password
export async function comparePasswords(
  plainPassword: string,
  hashedPassword: string
): Promise<boolean> {
  return await bcrypt.compare(plainPassword, hashedPassword);
}

export function setupAuth(app: Express) {
  // Cookie parser middleware (required for CSRF)
  app.use(cookieParser());

  // Session setup
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
        path: '/', // Ensure cookie is available for all paths
      },
      name: 'cruise_session', // Custom session name for easy identification
    })
  );

  // Initialize Passport
  app.use(passport.initialize());
  app.use(passport.session());
  
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
  
  // Rate limiting for authentication endpoints
  // Strict rate limiting - 5 attempts in 15 minutes, 
  // then account is locked for 12 hours (simulated with IP block)
  const failedLoginAttempts = new Map<string, { count: number, lockedUntil: Date | null }>();
  
  const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    limit: 5, // 5 failed attempts per IP per 15 minutes
    standardHeaders: true,
    legacyHeaders: false,
    message: { 
      message: 'Too many login attempts. Your account has been temporarily locked for security. Please try again after 12 hours or contact customer support for assistance.'
    },
    keyGenerator: (req) => {
      // Use the username if provided, otherwise fall back to IP
      const username = req.body?.username;
      return username || req.ip;
    },
    // Skip check if the lock has expired
    skip: (req, res) => {
      const key = req.body?.username || req.ip;
      const userAttempts = failedLoginAttempts.get(key);
      
      if (userAttempts && userAttempts.lockedUntil) {
        if (userAttempts.lockedUntil < new Date()) {
          // Lock expired, reset counter
          failedLoginAttempts.set(key, { count: 0, lockedUntil: null });
          return true;
        }
        // Still locked
        return false;
      }
      return true;
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

  // Authentication routes
  app.post("/api/auth/register", async (req: Request, res: Response) => {
    try {
      const userData = req.body as RegisterData;

      // Check if username already exists
      const existingUserByUsername = await storage.getUserByUsername(userData.username);
      if (existingUserByUsername) {
        return res.status(400).json({ message: "Username already exists" });
      }

      // Check if email already exists
      const existingUserByEmail = await storage.getUserByEmail(userData.email);
      if (existingUserByEmail) {
        return res.status(400).json({ message: "Email already exists" });
      }

      // Hash password
      const hashedPassword = await hashPassword(userData.password);

      // Create user
      const user = await storage.createUser({
        ...userData,
        password: hashedPassword,
      });

      // Remove password from response
      const { password, ...userWithoutPassword } = user;

      // Log in the user after registration
      req.login(user, (err) => {
        if (err) {
          return res.status(500).json({ message: "Error logging in after registration" });
        }
        return res.status(201).json(userWithoutPassword);
      });
    } catch (error) {
      console.error("Registration error:", error);
      res.status(500).json({ message: "Error registering user" });
    }
  });

  app.post("/api/auth/login", loginLimiter, (req: Request, res: Response, next: NextFunction) => {
    // Check if the username is already locked out
    const username = req.body.username;
    if (!username) {
      return res.status(400).json({ 
        message: "Username is required",
        field: "username" 
      });
    }

    // For debugging CSRF
    console.log('Login attempt headers:', {
      csrf: req.headers['csrf-token'],
      cookies: req.headers.cookie
    });

    const userAttempts = failedLoginAttempts.get(username);
    if (userAttempts && userAttempts.lockedUntil && userAttempts.lockedUntil > new Date()) {
      const remainingTime = Math.ceil((userAttempts.lockedUntil.getTime() - Date.now()) / (1000 * 60 * 60));
      return res.status(429).json({ 
        message: `Account temporarily locked for security. Please try again in ${remainingTime} hours or contact customer support.`,
        locked: true,
        lockExpiresIn: remainingTime 
      });
    }

    passport.authenticate("local", (err: Error, user: UserType, info: { message: string }) => {
      if (err) {
        return next(err);
      }
      
      if (!user) {
        // Increment failed login attempt counter
        const userAttempts = failedLoginAttempts.get(username) || { count: 0, lockedUntil: null };
        userAttempts.count += 1;
        
        // If this is the 5th attempt, lock the account for 12 hours
        if (userAttempts.count >= 5) {
          const lockUntil = new Date();
          lockUntil.setHours(lockUntil.getHours() + 12);
          userAttempts.lockedUntil = lockUntil;
          
          failedLoginAttempts.set(username, userAttempts);
          
          return res.status(429).json({ 
            message: "Account temporarily locked for security. Please try again after 12 hours or contact customer support.",
            locked: true,
            lockExpiresIn: 12
          });
        }
        
        failedLoginAttempts.set(username, userAttempts);
        
        // Provide a user-friendly error message
        let errorMessage = "Invalid username or password";
        if (info.message === "Invalid username") {
          errorMessage = "The username you entered doesn't exist.";
        } else if (info.message === "Invalid password") {
          errorMessage = "Incorrect password. Please try again.";
          // Show remaining attempts
          const remainingAttempts = 5 - userAttempts.count;
          errorMessage += ` (${remainingAttempts} ${remainingAttempts === 1 ? 'attempt' : 'attempts'} remaining)`;
        }
        
        return res.status(401).json({ 
          message: errorMessage,
          remainingAttempts: 5 - userAttempts.count
        });
      }
      
      // Successful login - reset any failed attempts
      if (failedLoginAttempts.has(username)) {
        failedLoginAttempts.delete(username);
      }
      
      req.login(user, (err) => {
        if (err) {
          return next(err);
        }
        
        // Remove password from response
        const { password, ...userWithoutPassword } = user;
        return res.json(userWithoutPassword);
      });
    })(req, res, next);
  });

  app.post("/api/auth/logout", (req: Request, res: Response) => {
    req.logout((err) => {
      if (err) {
        return res.status(500).json({ message: "Error logging out" });
      }
      res.json({ message: "Logged out successfully" });
    });
  });

  app.get("/api/auth/user", (req: Request, res: Response) => {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ message: "Not authenticated" });
    }
    // Remove password from response
    const { password, ...userWithoutPassword } = req.user as UserType;
    res.json(userWithoutPassword);
  });

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

  // Password reset
  app.post("/api/auth/reset-password", resetLimiter, async (req: Request, res: Response) => {
    try {
      const { token, password } = req.body;
      
      // Hash the new password
      const hashedPassword = await hashPassword(password);
      
      // Reset the password
      const success = await storage.resetPassword(token, hashedPassword);
      
      if (!success) {
        return res.status(400).json({ message: "Invalid or expired token" });
      }
      
      res.json({ message: "Password reset successfully" });
    } catch (error) {
      console.error("Password reset error:", error);
      res.status(500).json({ message: "Error resetting password" });
    }
  });

  // Middleware to check if user is authenticated
  app.use("/api/profile", (req: Request, res: Response, next: NextFunction) => {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ message: "Not authenticated" });
    }
    next();
  });

  // Update user profile
  app.patch("/api/profile", async (req: Request, res: Response) => {
    try {
      if (!req.isAuthenticated()) {
        return res.status(401).json({ message: "Not authenticated" });
      }

      const userId = (req.user as UserType).id;
      const userData = req.body;
      
      // Never allow password update through this endpoint
      delete userData.password;
      
      const updatedUser = await storage.updateUser(userId, userData);
      
      if (!updatedUser) {
        return res.status(404).json({ message: "User not found" });
      }
      
      // Remove password from response
      const { password, ...userWithoutPassword } = updatedUser;
      
      res.json(userWithoutPassword);
    } catch (error) {
      console.error("Profile update error:", error);
      res.status(500).json({ message: "Error updating profile" });
    }
  });

  // Change password
  app.post("/api/profile/change-password", async (req: Request, res: Response) => {
    try {
      if (!req.isAuthenticated()) {
        return res.status(401).json({ message: "Not authenticated" });
      }

      const userId = (req.user as UserType).id;
      const { currentPassword, newPassword } = req.body;
      
      // Get the user to verify current password
      const user = await storage.getUser(userId);
      
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
      
      // Verify current password
      const isMatch = await comparePasswords(currentPassword, user.password);
      
      if (!isMatch) {
        return res.status(400).json({ message: "Current password is incorrect" });
      }
      
      // Hash the new password
      const hashedPassword = await hashPassword(newPassword);
      
      // Update the password
      const updatedUser = await storage.updateUserPassword(userId, hashedPassword);
      
      if (!updatedUser) {
        return res.status(404).json({ message: "User not found" });
      }
      
      res.json({ message: "Password changed successfully" });
    } catch (error) {
      console.error("Password change error:", error);
      res.status(500).json({ message: "Error changing password" });
    }
  });
}

// Middleware to check if user is authenticated
export function isAuthenticated(req: Request, res: Response, next: NextFunction) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.status(401).json({ message: "Not authenticated" });
}