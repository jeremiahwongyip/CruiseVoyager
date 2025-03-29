import { 
  users, type User, type InsertUser,
  destinations, type Destination, type InsertDestination,
  cruises, type Cruise, type InsertCruise,
  bookings, type Booking, type InsertBooking,
  amenities, type Amenity, type InsertAmenity,
  testimonials, type Testimonial, type InsertTestimonial,
  enquiries, type Enquiry, type InsertEnquiry,
  enquiryResponses, type EnquiryResponse, type InsertEnquiryResponse,
  cabinTypes, type CabinType, type InsertCabinType,
  payments, type Payment, type InsertPayment
} from "@shared/schema";
import { db } from "./db";
import { eq, and, gt, lt, like, desc, asc, isNull, inArray, sql } from "drizzle-orm";
import { randomUUID } from "crypto";
import { PASSWORD_RESET_TOKEN_EXPIRY } from "./config";
import { IStorage } from "./storage";
import session from "express-session";
import connectPgSimple from "connect-pg-simple";
import { pool } from "./db";

/**
 * Database implementation of the storage interface using PostgreSQL and Drizzle ORM
 */
export class DatabaseStorage implements IStorage {
  sessionStore: session.Store;

  constructor() {
    const PgSession = connectPgSimple(session);
    this.sessionStore = new PgSession({
      pool,
      tableName: "session",
      createTableIfMissing: true,
    });
  }

  // User methods
  async getUser(id: number): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.id, id));
    return user;
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.username, username));
    return user;
  }

  async getUserByEmail(email: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.email, email));
    return user;
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const [user] = await db.insert(users).values(insertUser).returning();
    return user;
  }

  async updateUser(id: number, userData: Partial<InsertUser>): Promise<User | undefined> {
    const [updatedUser] = await db
      .update(users)
      .set({ ...userData, updatedAt: new Date() })
      .where(eq(users.id, id))
      .returning();
    return updatedUser;
  }

  async updateUserPassword(id: number, password: string): Promise<User | undefined> {
    const [updatedUser] = await db
      .update(users)
      .set({ password, updatedAt: new Date() })
      .where(eq(users.id, id))
      .returning();
    return updatedUser;
  }

  async updateUserLastLogin(id: number): Promise<User | undefined> {
    const [updatedUser] = await db
      .update(users)
      .set({ lastLogin: new Date(), updatedAt: new Date() })
      .where(eq(users.id, id))
      .returning();
    return updatedUser;
  }

  async createPasswordResetToken(email: string): Promise<string | undefined> {
    const [user] = await db.select().from(users).where(eq(users.email, email));
    
    if (!user) {
      return undefined;
    }
    
    const token = randomUUID();
    const expiryDate = new Date();
    expiryDate.setSeconds(expiryDate.getSeconds() + PASSWORD_RESET_TOKEN_EXPIRY);
    
    await db
      .update(users)
      .set({ 
        resetToken: token, 
        resetTokenExpiry: expiryDate,
        updatedAt: new Date()
      })
      .where(eq(users.id, user.id));
    
    return token;
  }

  async resetPassword(token: string, password: string): Promise<boolean> {
    // Find user with this token that hasn't expired
    const now = new Date();
    const [user] = await db
      .select()
      .from(users)
      .where(
        and(
          eq(users.resetToken, token),
          gt(users.resetTokenExpiry!, now)
        )
      );
    
    if (!user) {
      return false;
    }
    
    // Update password and clear token
    await db
      .update(users)
      .set({ 
        password, 
        resetToken: null, 
        resetTokenExpiry: null,
        updatedAt: new Date()
      })
      .where(eq(users.id, user.id));
    
    return true;
  }

  // Destination methods
  async getDestinations(): Promise<Destination[]> {
    return await db.select().from(destinations);
  }

  async getDestination(id: number): Promise<Destination | undefined> {
    const [destination] = await db
      .select()
      .from(destinations)
      .where(eq(destinations.id, id));
    return destination;
  }

  async createDestination(destination: InsertDestination): Promise<Destination> {
    const [newDestination] = await db
      .insert(destinations)
      .values(destination)
      .returning();
    return newDestination;
  }

  // Cruise methods
  async getCruises(): Promise<Cruise[]> {
    return await db.select().from(cruises);
  }

  async getCruise(id: number): Promise<Cruise | undefined> {
    const [cruise] = await db
      .select()
      .from(cruises)
      .where(eq(cruises.id, id));
    return cruise;
  }

  async getCruisesByDestination(destinationId: number): Promise<Cruise[]> {
    return await db
      .select()
      .from(cruises)
      .where(eq(cruises.destinationId, destinationId));
  }

  async createCruise(cruise: InsertCruise): Promise<Cruise> {
    const [newCruise] = await db
      .insert(cruises)
      .values(cruise)
      .returning();
    return newCruise;
  }

  async searchCruises(params: any): Promise<Cruise[]> {
    // Start with all cruises
    let query = `
      SELECT * FROM cruises 
      WHERE 1=1
    `;
    
    const queryParams: any[] = [];
    let paramIndex = 1;
    
    // Filter by destination
    if (params.destination) {
      query += ` AND destination_id = $${paramIndex}`;
      queryParams.push(parseInt(params.destination));
      paramIndex++;
    }
    
    // Filter by departure date (using custom SQL for array handling)
    if (params.departureDate) {
      const departureDate = new Date(params.departureDate).toISOString().split('T')[0];
      query += ` AND available_dates @> ARRAY[$${paramIndex}]::date[]`;
      queryParams.push(departureDate);
      paramIndex++;
    }
    
    // Filter by duration
    if (params.duration) {
      query += ` AND duration = $${paramIndex}`;
      queryParams.push(parseInt(params.duration));
      paramIndex++;
    }
    
    // Filter by number of travelers
    if (params.travelers) {
      query += ` AND id IN (
        SELECT cruise_id FROM cabin_types 
        WHERE capacity >= $${paramIndex}
      )`;
      queryParams.push(parseInt(params.travelers));
      paramIndex++;
    }
    
    // Use raw query to execute the SQL
    const { rows } = await pool.query(query, queryParams);
    return rows as Cruise[];
  }

  // Cabin Types methods
  async getCabinTypes(cruiseId: number): Promise<CabinType[]> {
    return await db
      .select()
      .from(cabinTypes)
      .where(eq(cabinTypes.cruiseId, cruiseId));
  }

  async getCabinType(id: number): Promise<CabinType | undefined> {
    const [cabinType] = await db
      .select()
      .from(cabinTypes)
      .where(eq(cabinTypes.id, id));
    return cabinType;
  }

  async createCabinType(cabinType: InsertCabinType): Promise<CabinType> {
    const [newCabinType] = await db
      .insert(cabinTypes)
      .values(cabinType)
      .returning();
    return newCabinType;
  }

  // Booking methods
  async getBookings(userId: number): Promise<Booking[]> {
    return await db
      .select()
      .from(bookings)
      .where(eq(bookings.userId, userId))
      .orderBy(desc(bookings.bookingDate));
  }

  async getBooking(id: number): Promise<Booking | undefined> {
    const [booking] = await db
      .select()
      .from(bookings)
      .where(eq(bookings.id, id));
    return booking;
  }

  async getBookingByReference(reference: string): Promise<Booking | undefined> {
    const [booking] = await db
      .select()
      .from(bookings)
      .where(eq(bookings.bookingReference, reference));
    return booking;
  }

  async createBooking(booking: InsertBooking): Promise<Booking> {
    // Generate a unique booking reference
    const bookingReference = `BK${Date.now().toString().slice(-6)}${Math.floor(Math.random() * 1000).toString().padStart(3, '0')}`;
    
    // Create initial status history as JSON
    const initialStatusHistory = JSON.stringify([
      { status: "pending", timestamp: new Date().toISOString() }
    ]);
    
    const [newBooking] = await db
      .insert(bookings)
      .values({
        ...booking,
        bookingReference,
        statusHistory: initialStatusHistory as any
      })
      .returning();
    
    return newBooking;
  }

  async updateBookingStatus(id: number, status: string): Promise<Booking | undefined> {
    const [booking] = await db.select().from(bookings).where(eq(bookings.id, id));
    
    if (!booking) {
      return undefined;
    }
    
    // Parse and update status history
    let statusHistory = [];
    if (booking.statusHistory) {
      try {
        statusHistory = JSON.parse(booking.statusHistory as string);
      } catch (e) {
        // If parsing fails, start with empty array
        statusHistory = [];
      }
    }
    
    // Add new status
    statusHistory.push({ status, timestamp: new Date().toISOString() });
    
    const [updatedBooking] = await db
      .update(bookings)
      .set({ 
        status: status as any, // Type casting needed here due to enums
        statusHistory: JSON.stringify(statusHistory) as any,
        updatedAt: new Date()
      })
      .where(eq(bookings.id, id))
      .returning();
    
    return updatedBooking;
  }

  async cancelBooking(id: number, reason: string, cancellationNotes?: string): Promise<Booking | undefined> {
    const [booking] = await db.select().from(bookings).where(eq(bookings.id, id));
    
    if (!booking) {
      return undefined;
    }
    
    // Parse and update status history
    let statusHistory = [];
    if (booking.statusHistory) {
      try {
        statusHistory = JSON.parse(booking.statusHistory as string);
      } catch (e) {
        // If parsing fails, start with empty array
        statusHistory = [];
      }
    }
    
    // Add cancelled status
    statusHistory.push({ status: "cancelled", timestamp: new Date().toISOString() });
    
    const [updatedBooking] = await db
      .update(bookings)
      .set({ 
        status: "cancelled", 
        cancellationReason: reason as any, // Type casting needed here due to enums
        cancellationNotes,
        cancellationDate: new Date(),
        statusHistory: JSON.stringify(statusHistory) as any,
        updatedAt: new Date()
      })
      .where(eq(bookings.id, id))
      .returning();
    
    return updatedBooking;
  }

  async updateBookingStatusHistory(id: number, status: string): Promise<Booking | undefined> {
    const [booking] = await db.select().from(bookings).where(eq(bookings.id, id));
    
    if (!booking) {
      return undefined;
    }
    
    // Parse and update status history
    let statusHistory = [];
    if (booking.statusHistory) {
      try {
        statusHistory = JSON.parse(booking.statusHistory as string);
      } catch (e) {
        // If parsing fails, start with empty array
        statusHistory = [];
      }
    }
    
    // Add new status
    statusHistory.push({ status, timestamp: new Date().toISOString() });
    
    const [updatedBooking] = await db
      .update(bookings)
      .set({ 
        statusHistory: JSON.stringify(statusHistory) as any,
        updatedAt: new Date()
      })
      .where(eq(bookings.id, id))
      .returning();
    
    return updatedBooking;
  }

  async processRefund(bookingId: number, amount: number): Promise<Booking | undefined> {
    const [booking] = await db.select().from(bookings).where(eq(bookings.id, bookingId));
    
    if (!booking) {
      return undefined;
    }
    
    // Parse and update status history
    let statusHistory = [];
    if (booking.statusHistory) {
      try {
        statusHistory = JSON.parse(booking.statusHistory as string);
      } catch (e) {
        // If parsing fails, start with empty array
        statusHistory = [];
      }
    }
    
    // Add refunded status
    statusHistory.push({ status: "refunded", timestamp: new Date().toISOString() });
    
    const [updatedBooking] = await db
      .update(bookings)
      .set({ 
        status: "refunded",
        refundAmount: amount,
        refundDate: new Date(),
        statusHistory: JSON.stringify(statusHistory) as any,
        updatedAt: new Date()
      })
      .where(eq(bookings.id, bookingId))
      .returning();
    
    return updatedBooking;
  }

  async checkInPassengers(bookingId: number): Promise<Booking | undefined> {
    const [booking] = await db.select().from(bookings).where(eq(bookings.id, bookingId));
    
    if (!booking) {
      return undefined;
    }
    
    const [updatedBooking] = await db
      .update(bookings)
      .set({ 
        checkedIn: true,
        checkInDate: new Date(),
        updatedAt: new Date()
      })
      .where(eq(bookings.id, bookingId))
      .returning();
    
    return updatedBooking;
  }

  async getUpcomingBookings(userId: number): Promise<Booking[]> {
    const today = new Date().toISOString().split('T')[0]; // Format as YYYY-MM-DD
    
    return await db
      .select()
      .from(bookings)
      .where(
        and(
          eq(bookings.userId, userId),
          sql`${bookings.departureDate} > ${today}`, // Use raw SQL for date comparison
          inArray(bookings.status, ["pending", "confirmed"])
        )
      )
      .orderBy(asc(bookings.departureDate));
  }

  async getPastBookings(userId: number): Promise<Booking[]> {
    const today = new Date().toISOString().split('T')[0]; // Format as YYYY-MM-DD
    
    return await db
      .select()
      .from(bookings)
      .where(
        and(
          eq(bookings.userId, userId),
          sql`${bookings.returnDate} < ${today}`, // Use raw SQL for date comparison
          inArray(bookings.status, ["in_progress", "completed", "cancelled", "refunded"])
        )
      )
      .orderBy(desc(bookings.returnDate));
  }

  // Payment methods
  async getPayments(bookingId: number): Promise<Payment[]> {
    return await db
      .select()
      .from(payments)
      .where(eq(payments.bookingId, bookingId))
      .orderBy(desc(payments.paymentDate));
  }

  async getPayment(id: number): Promise<Payment | undefined> {
    const [payment] = await db
      .select()
      .from(payments)
      .where(eq(payments.id, id));
    return payment;
  }

  async createPayment(payment: InsertPayment): Promise<Payment> {
    const [newPayment] = await db
      .insert(payments)
      .values(payment)
      .returning();
    return newPayment;
  }

  async updatePaymentStatus(id: number, status: string): Promise<Payment | undefined> {
    const [updatedPayment] = await db
      .update(payments)
      .set({ status: status as any }) // Type casting needed here due to enums
      .where(eq(payments.id, id))
      .returning();
    return updatedPayment;
  }

  async processStripePayment(bookingId: number, paymentData: any): Promise<Payment | undefined> {
    // In a real app, you would integrate with Stripe here
    // This is a simplified implementation
    const [newPayment] = await db
      .insert(payments)
      .values({
        bookingId,
        amount: paymentData.amount,
        currency: paymentData.currency || "USD",
        paymentMethod: "stripe",
        transactionId: `tr_${Date.now()}`,
        paymentIntentId: paymentData.paymentIntentId,
        status: "completed",
        cardLast4: paymentData.cardLast4,
        expiryMonth: paymentData.expiryMonth,
        expiryYear: paymentData.expiryYear,
        cardholderName: paymentData.cardholderName,
        billingAddress: paymentData.billingAddress
      })
      .returning();
    
    // Update booking status to confirmed
    if (newPayment) {
      await this.updateBookingStatus(bookingId, "confirmed");
    }
    
    return newPayment;
  }

  async refundPayment(id: number, amount: number): Promise<Payment | undefined> {
    const [payment] = await db
      .select()
      .from(payments)
      .where(eq(payments.id, id));
    
    if (!payment) {
      return undefined;
    }
    
    const [updatedPayment] = await db
      .update(payments)
      .set({
        status: "refunded",
        refundAmount: amount,
        refundDate: new Date()
      })
      .where(eq(payments.id, id))
      .returning();
    
    return updatedPayment;
  }

  async getPaymentsByStatus(status: string): Promise<Payment[]> {
    return await db
      .select()
      .from(payments)
      .where(eq(payments.status, status as any)) // Type casting needed here due to enums
      .orderBy(desc(payments.paymentDate));
  }

  // Amenity methods
  async getAmenities(): Promise<Amenity[]> {
    return await db.select().from(amenities);
  }

  async getAmenity(id: number): Promise<Amenity | undefined> {
    const [amenity] = await db
      .select()
      .from(amenities)
      .where(eq(amenities.id, id));
    return amenity;
  }

  async createAmenity(amenity: InsertAmenity): Promise<Amenity> {
    const [newAmenity] = await db
      .insert(amenities)
      .values(amenity)
      .returning();
    return newAmenity;
  }

  // Testimonial methods
  async getTestimonials(): Promise<Testimonial[]> {
    return await db
      .select()
      .from(testimonials)
      .where(eq(testimonials.isVerified, true))
      .orderBy(desc(testimonials.createdAt));
  }

  async getTestimonialsByCruise(cruiseId: number): Promise<Testimonial[]> {
    return await db
      .select()
      .from(testimonials)
      .where(
        and(
          eq(testimonials.cruiseId, cruiseId),
          eq(testimonials.isVerified, true)
        )
      )
      .orderBy(desc(testimonials.createdAt));
  }

  async getTestimonial(id: number): Promise<Testimonial | undefined> {
    const [testimonial] = await db
      .select()
      .from(testimonials)
      .where(eq(testimonials.id, id));
    return testimonial;
  }

  async createTestimonial(testimonial: InsertTestimonial): Promise<Testimonial> {
    const [newTestimonial] = await db
      .insert(testimonials)
      .values(testimonial)
      .returning();
    return newTestimonial;
  }

  async verifyTestimonial(id: number): Promise<Testimonial | undefined> {
    const [verifiedTestimonial] = await db
      .update(testimonials)
      .set({ isVerified: true })
      .where(eq(testimonials.id, id))
      .returning();
    return verifiedTestimonial;
  }

  // Enquiry methods
  async getEnquiries(): Promise<Enquiry[]> {
    return await db
      .select()
      .from(enquiries)
      .orderBy(desc(enquiries.createdAt));
  }

  async getEnquiriesByUser(userId: number): Promise<Enquiry[]> {
    return await db
      .select()
      .from(enquiries)
      .where(eq(enquiries.userId, userId))
      .orderBy(desc(enquiries.createdAt));
  }

  async getEnquiry(id: number): Promise<Enquiry | undefined> {
    const [enquiry] = await db
      .select()
      .from(enquiries)
      .where(eq(enquiries.id, id));
    return enquiry;
  }

  async createEnquiry(enquiry: InsertEnquiry): Promise<Enquiry> {
    const [newEnquiry] = await db
      .insert(enquiries)
      .values(enquiry)
      .returning();
    return newEnquiry;
  }

  async updateEnquiryStatus(id: number, status: string): Promise<Enquiry | undefined> {
    const [updatedEnquiry] = await db
      .update(enquiries)
      .set({ 
        status: status as any, // Type casting needed here due to enums
        updatedAt: new Date()
      })
      .where(eq(enquiries.id, id))
      .returning();
    return updatedEnquiry;
  }

  async assignEnquiry(id: number, userId: number): Promise<Enquiry | undefined> {
    const [updatedEnquiry] = await db
      .update(enquiries)
      .set({ 
        assignedToUserId: userId,
        updatedAt: new Date()
      })
      .where(eq(enquiries.id, id))
      .returning();
    return updatedEnquiry;
  }

  // Enquiry Response methods
  async getEnquiryResponses(enquiryId: number): Promise<EnquiryResponse[]> {
    return await db
      .select()
      .from(enquiryResponses)
      .where(eq(enquiryResponses.enquiryId, enquiryId))
      .orderBy(asc(enquiryResponses.respondedAt));
  }

  async createEnquiryResponse(response: InsertEnquiryResponse): Promise<EnquiryResponse> {
    const [newResponse] = await db
      .insert(enquiryResponses)
      .values(response)
      .returning();
    
    // Update enquiry status to responded
    await this.updateEnquiryStatus(response.enquiryId, "responded");
    
    return newResponse;
  }
}