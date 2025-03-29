// Database connection configuration
export const DB_URL = process.env.DATABASE_URL || '';

// Application settings
// Generate a secure random string if APP_SECRET is not set
import crypto from 'crypto';
export const APP_SECRET = process.env.APP_SECRET || 
  crypto.randomBytes(32).toString('hex');
export const PORT = process.env.PORT || 3000;

// Token settings
export const TOKEN_EXPIRY = 60 * 60 * 24; // 24 hours

// Email settings for password reset
export const PASSWORD_RESET_TOKEN_EXPIRY = 60 * 60 * 2; // 2 hours