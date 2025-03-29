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
import { randomUUID } from "crypto";
import { createHash } from "crypto";
import { DB_URL } from "./config";
import pkg from "pg";

// modify the interface with any CRUD methods
// you might need

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

export class MemStorage implements IStorage {
  private usersData: Map<number, User>;
  private destinationsData: Map<number, Destination>;
  private cruisesData: Map<number, Cruise>;
  private bookingsData: Map<number, Booking>;
  private amenitiesData: Map<number, Amenity>;
  private testimonialsData: Map<number, Testimonial>;
  private cabinTypesData: Map<number, CabinType>;
  private paymentsData: Map<number, Payment>;
  private enquiriesData: Map<number, Enquiry>;
  private enquiryResponsesData: Map<number, EnquiryResponse>;
  
  private currentUserIds: number;
  private currentDestinationIds: number;
  private currentCruiseIds: number;
  private currentBookingIds: number;
  private currentAmenityIds: number;
  private currentTestimonialIds: number;
  private currentCabinTypeIds: number;
  private currentPaymentIds: number;
  private currentEnquiryIds: number;
  private currentEnquiryResponseIds: number;

  constructor() {
    this.usersData = new Map();
    this.destinationsData = new Map();
    this.cruisesData = new Map();
    this.bookingsData = new Map();
    this.amenitiesData = new Map();
    this.testimonialsData = new Map();
    this.cabinTypesData = new Map();
    this.paymentsData = new Map();
    this.enquiriesData = new Map();
    this.enquiryResponsesData = new Map();
    
    this.currentUserIds = 1;
    this.currentDestinationIds = 1;
    this.currentCruiseIds = 1;
    this.currentBookingIds = 1;
    this.currentAmenityIds = 1;
    this.currentTestimonialIds = 1;
    this.currentCabinTypeIds = 1;
    this.currentPaymentIds = 1;
    this.currentEnquiryIds = 1;
    this.currentEnquiryResponseIds = 1;
    
    // Initialize with sample data
    this.initSampleData();
  }

  // User methods
  async getUser(id: number): Promise<User | undefined> {
    return this.usersData.get(id);
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    return Array.from(this.usersData.values()).find(
      (user) => user.username === username,
    );
  }
  
  async getUserByEmail(email: string): Promise<User | undefined> {
    return Array.from(this.usersData.values()).find(
      (user) => user.email === email,
    );
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const id = this.currentUserIds++;
    const now = new Date();
    const user: User = { 
      ...insertUser, 
      id,
      createdAt: now,
      updatedAt: now,
      lastLogin: null,
      isVerified: false,
      resetToken: null,
      resetTokenExpiry: null,
      firstName: insertUser.firstName || null,
      lastName: insertUser.lastName || null,
      phone: insertUser.phone || null,
      address: insertUser.address || null,
      city: insertUser.city || null,
      state: insertUser.state || null,
      zipCode: insertUser.zipCode || null,
      country: insertUser.country || null
    };
    this.usersData.set(id, user);
    return user;
  }
  
  async updateUser(id: number, userData: Partial<InsertUser>): Promise<User | undefined> {
    const existingUser = this.usersData.get(id);
    if (!existingUser) return undefined;
    
    const updatedUser = { 
      ...existingUser, 
      ...userData,
      updatedAt: new Date()
    };
    this.usersData.set(id, updatedUser);
    return updatedUser;
  }
  
  async updateUserPassword(id: number, password: string): Promise<User | undefined> {
    const existingUser = this.usersData.get(id);
    if (!existingUser) return undefined;
    
    const updatedUser = { 
      ...existingUser, 
      password,
      updatedAt: new Date(),
      resetToken: null,
      resetTokenExpiry: null
    };
    this.usersData.set(id, updatedUser);
    return updatedUser;
  }
  
  async updateUserLastLogin(id: number): Promise<User | undefined> {
    const existingUser = this.usersData.get(id);
    if (!existingUser) return undefined;
    
    const updatedUser = { 
      ...existingUser, 
      lastLogin: new Date()
    };
    this.usersData.set(id, updatedUser);
    return updatedUser;
  }
  
  async createPasswordResetToken(email: string): Promise<string | undefined> {
    const user = await this.getUserByEmail(email);
    if (!user) return undefined;
    
    const token = randomUUID();
    const expiry = new Date();
    expiry.setHours(expiry.getHours() + 2); // Token valid for 2 hours
    
    const updatedUser = { 
      ...user, 
      resetToken: token,
      resetTokenExpiry: expiry,
      updatedAt: new Date()
    };
    this.usersData.set(user.id, updatedUser);
    return token;
  }
  
  async resetPassword(token: string, password: string): Promise<boolean> {
    const user = Array.from(this.usersData.values()).find(
      (user) => user.resetToken === token && 
                user.resetTokenExpiry && 
                user.resetTokenExpiry > new Date()
    );
    
    if (!user) return false;
    
    const updatedUser = { 
      ...user, 
      password,
      resetToken: null,
      resetTokenExpiry: null,
      updatedAt: new Date()
    };
    this.usersData.set(user.id, updatedUser);
    return true;
  }

  // Destination methods
  async getDestinations(): Promise<Destination[]> {
    return Array.from(this.destinationsData.values());
  }
  
  async getDestination(id: number): Promise<Destination | undefined> {
    return this.destinationsData.get(id);
  }
  
  async createDestination(destination: InsertDestination): Promise<Destination> {
    const id = this.currentDestinationIds++;
    const newDestination: Destination = { ...destination, id };
    this.destinationsData.set(id, newDestination);
    return newDestination;
  }

  // Cruise methods
  async getCruises(): Promise<Cruise[]> {
    return Array.from(this.cruisesData.values());
  }
  
  async getCruise(id: number): Promise<Cruise | undefined> {
    return this.cruisesData.get(id);
  }
  
  async getCruisesByDestination(destinationId: number): Promise<Cruise[]> {
    return Array.from(this.cruisesData.values()).filter(
      (cruise) => cruise.destinationId === destinationId
    );
  }
  
  async createCruise(cruise: InsertCruise): Promise<Cruise> {
    const id = this.currentCruiseIds++;
    const newCruise: Cruise = { 
      ...cruise, 
      id,
      originalPrice: cruise.originalPrice || null,
      isBestSeller: cruise.isBestSeller || false,
      isNewItinerary: cruise.isNewItinerary || false,
      availableDates: cruise.availableDates || null
    };
    this.cruisesData.set(id, newCruise);
    return newCruise;
  }
  
  // Cabin Types methods
  async getCabinTypes(cruiseId: number): Promise<CabinType[]> {
    return Array.from(this.cabinTypesData.values()).filter(
      cabin => cabin.cruiseId === cruiseId
    );
  }
  
  async getCabinType(id: number): Promise<CabinType | undefined> {
    return this.cabinTypesData.get(id);
  }
  
  async createCabinType(cabinType: InsertCabinType): Promise<CabinType> {
    const id = this.currentCabinTypeIds++;
    const newCabinType: CabinType = {
      ...cabinType,
      id,
      imageUrl: cabinType.imageUrl || null,
      priceModifier: cabinType.priceModifier || 0,
      amenities: cabinType.amenities || null
    };
    this.cabinTypesData.set(id, newCabinType);
    return newCabinType;
  }
  
  async searchCruises(params: any): Promise<Cruise[]> {
    let results = Array.from(this.cruisesData.values());
    
    if (params.destination && params.destination !== "Any Destination") {
      const destination = Array.from(this.destinationsData.values()).find(
        d => d.name === params.destination
      );
      if (destination) {
        results = results.filter(cruise => cruise.destinationId === destination.id);
      }
    }
    
    if (params.duration && params.duration !== "Any Length") {
      // Handle duration filtering
      switch(params.duration) {
        case "2-5 Days":
          results = results.filter(cruise => cruise.duration >= 2 && cruise.duration <= 5);
          break;
        case "6-9 Days":
          results = results.filter(cruise => cruise.duration >= 6 && cruise.duration <= 9);
          break;
        case "10+ Days":
          results = results.filter(cruise => cruise.duration >= 10);
          break;
      }
    }
    
    return results;
  }

  // Booking methods
  async getBookings(userId: number): Promise<Booking[]> {
    return Array.from(this.bookingsData.values()).filter(
      (booking) => booking.userId === userId
    );
  }
  
  async getBooking(id: number): Promise<Booking | undefined> {
    return this.bookingsData.get(id);
  }
  
  async getBookingByReference(reference: string): Promise<Booking | undefined> {
    return Array.from(this.bookingsData.values()).find(
      (booking) => booking.bookingReference === reference
    );
  }
  
  async createBooking(booking: InsertBooking): Promise<Booking> {
    const id = this.currentBookingIds++;
    const now = new Date();
    const bookingReference = `BK-${Math.floor(Math.random() * 10000)}-${id}`;
    
    const newBooking: Booking = { 
      ...booking, 
      id,
      bookingDate: now,
      updatedAt: now,
      bookingReference,
      status: booking.status || "pending",
      specialRequests: booking.specialRequests || null,
      paymentId: booking.paymentId || null,
      paymentStatus: booking.paymentStatus || null
    };
    this.bookingsData.set(id, newBooking);
    return newBooking;
  }
  
  async updateBookingStatus(id: number, status: string): Promise<Booking | undefined> {
    const existingBooking = this.bookingsData.get(id);
    if (!existingBooking) return undefined;
    
    const updatedBooking = { 
      ...existingBooking, 
      status: status as "pending" | "confirmed" | "completed" | "cancelled",
      updatedAt: new Date()
    };
    this.bookingsData.set(id, updatedBooking);
    return updatedBooking;
  }
  
  async cancelBooking(id: number, reason: string, cancellationReason?: string): Promise<Booking | undefined> {
    const existingBooking = this.bookingsData.get(id);
    if (!existingBooking) return undefined;
    
    const now = new Date();
    // Create status history if it doesn't exist
    const statusHistory = existingBooking.statusHistory || [];
    statusHistory.push({
      from: existingBooking.status,
      to: "cancelled",
      timestamp: now.toISOString(),
      reason: cancellationReason || "customer_request"
    });
    
    const updatedBooking = { 
      ...existingBooking, 
      status: "cancelled" as const,
      specialRequests: reason || existingBooking.specialRequests,
      updatedAt: now,
      cancellationDate: now,
      cancellationReason: cancellationReason || "customer_request" as const,
      cancellationNotes: reason,
      statusHistory
    };
    this.bookingsData.set(id, updatedBooking);
    return updatedBooking;
  }
  
  async updateBookingStatusHistory(id: number, status: string): Promise<Booking | undefined> {
    const existingBooking = this.bookingsData.get(id);
    if (!existingBooking) return undefined;
    
    const now = new Date();
    const statusHistory = existingBooking.statusHistory || [];
    statusHistory.push({
      from: existingBooking.status,
      to: status,
      timestamp: now.toISOString()
    });
    
    const updatedBooking = { 
      ...existingBooking, 
      status: status as any, // Cast to any to avoid type issues
      updatedAt: now,
      statusHistory
    };
    this.bookingsData.set(id, updatedBooking);
    return updatedBooking;
  }
  
  async processRefund(bookingId: number, amount: number): Promise<Booking | undefined> {
    const existingBooking = this.bookingsData.get(bookingId);
    if (!existingBooking) return undefined;
    
    const now = new Date();
    const updatedBooking = { 
      ...existingBooking, 
      status: "refunded" as const,
      paymentStatus: "refunded" as any,
      refundAmount: amount,
      refundDate: now,
      updatedAt: now
    };
    this.bookingsData.set(bookingId, updatedBooking);
    
    // Also update the payment if it exists
    if (existingBooking.paymentId) {
      const payment = Array.from(this.paymentsData.values()).find(
        p => p.id.toString() === existingBooking.paymentId
      );
      if (payment) {
        const updatedPayment = {
          ...payment,
          status: "refunded" as any,
          refundAmount: amount,
          refundDate: now
        };
        this.paymentsData.set(payment.id, updatedPayment);
      }
    }
    
    return updatedBooking;
  }
  
  async checkInPassengers(bookingId: number): Promise<Booking | undefined> {
    const existingBooking = this.bookingsData.get(bookingId);
    if (!existingBooking) return undefined;
    
    const now = new Date();
    const updatedBooking = { 
      ...existingBooking, 
      checkedIn: true,
      checkInDate: now,
      updatedAt: now
    };
    this.bookingsData.set(bookingId, updatedBooking);
    return updatedBooking;
  }
  
  async getUpcomingBookings(userId: number): Promise<Booking[]> {
    const now = new Date();
    return Array.from(this.bookingsData.values()).filter(
      booking => 
        booking.userId === userId && 
        booking.status !== "cancelled" &&
        booking.status !== "refunded" &&
        new Date(booking.departureDate) > now
    );
  }
  
  async getPastBookings(userId: number): Promise<Booking[]> {
    const now = new Date();
    return Array.from(this.bookingsData.values()).filter(
      booking => 
        booking.userId === userId && 
        (booking.status === "completed" || new Date(booking.returnDate) < now)
    );
  }
  
  // Payment methods
  async getPayments(bookingId: number): Promise<Payment[]> {
    return Array.from(this.paymentsData.values()).filter(
      (payment) => payment.bookingId === bookingId
    );
  }
  
  async getPayment(id: number): Promise<Payment | undefined> {
    return this.paymentsData.get(id);
  }
  
  async createPayment(payment: InsertPayment): Promise<Payment> {
    const id = this.currentPaymentIds++;
    const newPayment: Payment = {
      ...payment,
      id,
      paymentDate: new Date(),
      currency: payment.currency || "USD",
      transactionId: payment.transactionId || null,
      billingAddress: payment.billingAddress || null
    };
    this.paymentsData.set(id, newPayment);
    
    // Update booking payment status if a bookingId is provided
    if (payment.bookingId) {
      const booking = this.bookingsData.get(payment.bookingId);
      if (booking) {
        const updatedBooking = {
          ...booking,
          paymentId: id.toString(),
          paymentStatus: payment.status,
          status: payment.status === 'completed' ? 'confirmed' as const : booking.status,
          updatedAt: new Date()
        };
        this.bookingsData.set(payment.bookingId, updatedBooking);
      }
    }
    
    return newPayment;
  }
  
  async updatePaymentStatus(id: number, status: string): Promise<Payment | undefined> {
    const existingPayment = this.paymentsData.get(id);
    if (!existingPayment) return undefined;
    
    const updatedPayment = {
      ...existingPayment,
      status: status as any // Cast to avoid type issues
    };
    this.paymentsData.set(id, updatedPayment);
    
    // Update booking payment status if this payment is associated with a booking
    const booking = this.bookingsData.get(existingPayment.bookingId);
    if (booking) {
      const updatedBooking = {
        ...booking,
        paymentStatus: status as any, // Cast to avoid type issues
        status: status === 'completed' ? 'confirmed' as const : booking.status,
        updatedAt: new Date()
      };
      this.bookingsData.set(existingPayment.bookingId, updatedBooking);
    }
    
    return updatedPayment;
  }
  
  async processStripePayment(bookingId: number, paymentData: any): Promise<Payment | undefined> {
    const booking = this.bookingsData.get(bookingId);
    if (!booking) return undefined;
    
    const now = new Date();
    
    // Create payment record
    const id = this.currentPaymentIds++;
    const newPayment: Payment = {
      id,
      bookingId,
      amount: booking.totalPrice,
      currency: "USD",
      status: "processing" as any, // Start as processing
      paymentMethod: "stripe" as any,
      transactionId: null,
      paymentIntentId: paymentData.paymentIntentId || null,
      paymentDate: now,
      billingAddress: paymentData.billingAddress || null,
      cardLast4: paymentData.cardLast4 || null,
      expiryMonth: paymentData.expiryMonth || null,
      expiryYear: paymentData.expiryYear || null,
      cardholderName: paymentData.cardholderName || null,
      refundAmount: null,
      refundDate: null,
      gatewayResponse: { received: now } as any
    };
    
    this.paymentsData.set(id, newPayment);
    
    // Update booking with payment information
    const updatedBooking = {
      ...booking,
      paymentStatus: "processing" as any,
      updatedAt: now
    };
    this.bookingsData.set(bookingId, updatedBooking);
    
    return newPayment;
  }
  
  async refundPayment(id: number, amount: number): Promise<Payment | undefined> {
    const existingPayment = this.paymentsData.get(id);
    if (!existingPayment) return undefined;
    
    const now = new Date();
    const updatedPayment = {
      ...existingPayment,
      status: amount === existingPayment.amount ? "refunded" as any : "partially_refunded" as any,
      refundAmount: amount,
      refundDate: now,
      gatewayResponse: { 
        ...existingPayment.gatewayResponse as any,
        refunded: now 
      }
    };
    this.paymentsData.set(id, updatedPayment);
    
    // Also update the booking if it exists
    const booking = this.bookingsData.get(existingPayment.bookingId);
    if (booking) {
      const updatedBooking = {
        ...booking,
        paymentStatus: updatedPayment.status,
        status: amount === existingPayment.amount ? "refunded" as const : booking.status,
        refundAmount: amount,
        refundDate: now,
        updatedAt: now
      };
      this.bookingsData.set(existingPayment.bookingId, updatedBooking);
    }
    
    return updatedPayment;
  }
  
  async getPaymentsByStatus(status: string): Promise<Payment[]> {
    return Array.from(this.paymentsData.values()).filter(
      payment => payment.status === status
    );
  }

  // Amenity methods
  async getAmenities(): Promise<Amenity[]> {
    return Array.from(this.amenitiesData.values());
  }
  
  async getAmenity(id: number): Promise<Amenity | undefined> {
    return this.amenitiesData.get(id);
  }
  
  async createAmenity(amenity: InsertAmenity): Promise<Amenity> {
    const id = this.currentAmenityIds++;
    const newAmenity: Amenity = { 
      ...amenity, 
      id,
      category: amenity.category || null 
    };
    this.amenitiesData.set(id, newAmenity);
    return newAmenity;
  }

  // Testimonial methods
  async getTestimonials(): Promise<Testimonial[]> {
    return Array.from(this.testimonialsData.values());
  }
  
  async getTestimonialsByCruise(cruiseId: number): Promise<Testimonial[]> {
    return Array.from(this.testimonialsData.values()).filter(
      (testimonial) => testimonial.cruiseId === cruiseId
    );
  }
  
  async getTestimonial(id: number): Promise<Testimonial | undefined> {
    return this.testimonialsData.get(id);
  }
  
  async createTestimonial(testimonial: InsertTestimonial): Promise<Testimonial> {
    const id = this.currentTestimonialIds++;
    const now = new Date();
    const newTestimonial: Testimonial = { 
      ...testimonial, 
      id,
      createdAt: now,
      isVerified: false,
      cruiseId: testimonial.cruiseId || null,
      userId: testimonial.userId || null,
      avatarUrl: testimonial.avatarUrl || null
    };
    this.testimonialsData.set(id, newTestimonial);
    return newTestimonial;
  }
  
  async verifyTestimonial(id: number): Promise<Testimonial | undefined> {
    const existingTestimonial = this.testimonialsData.get(id);
    if (!existingTestimonial) return undefined;
    
    const updatedTestimonial = { 
      ...existingTestimonial, 
      isVerified: true
    };
    this.testimonialsData.set(id, updatedTestimonial);
    return updatedTestimonial;
  }
  
  // Enquiry methods (Contact Us)
  async getEnquiries(): Promise<Enquiry[]> {
    return Array.from(this.enquiriesData.values());
  }
  
  async getEnquiriesByUser(userId: number): Promise<Enquiry[]> {
    return Array.from(this.enquiriesData.values()).filter(
      (enquiry) => enquiry.userId === userId
    );
  }
  
  async getEnquiry(id: number): Promise<Enquiry | undefined> {
    return this.enquiriesData.get(id);
  }
  
  async createEnquiry(enquiry: InsertEnquiry): Promise<Enquiry> {
    const id = this.currentEnquiryIds++;
    const now = new Date();
    const newEnquiry: Enquiry = {
      ...enquiry,
      id,
      status: "submitted",
      createdAt: now,
      updatedAt: now,
      assignedToUserId: null,
      userId: enquiry.userId || null,
      phone: enquiry.phone || null
    };
    this.enquiriesData.set(id, newEnquiry);
    return newEnquiry;
  }
  
  async updateEnquiryStatus(id: number, status: string): Promise<Enquiry | undefined> {
    const existingEnquiry = this.enquiriesData.get(id);
    if (!existingEnquiry) return undefined;
    
    const updatedEnquiry = {
      ...existingEnquiry,
      status: status as "submitted" | "in_review" | "responded" | "closed",
      updatedAt: new Date()
    };
    this.enquiriesData.set(id, updatedEnquiry);
    return updatedEnquiry;
  }
  
  async assignEnquiry(id: number, userId: number): Promise<Enquiry | undefined> {
    const existingEnquiry = this.enquiriesData.get(id);
    if (!existingEnquiry) return undefined;
    
    const updatedEnquiry = {
      ...existingEnquiry,
      assignedToUserId: userId,
      status: existingEnquiry.status === "submitted" ? "in_review" as const : existingEnquiry.status,
      updatedAt: new Date()
    };
    this.enquiriesData.set(id, updatedEnquiry);
    return updatedEnquiry;
  }
  
  // Enquiry Response methods
  async getEnquiryResponses(enquiryId: number): Promise<EnquiryResponse[]> {
    return Array.from(this.enquiryResponsesData.values()).filter(
      (response) => response.enquiryId === enquiryId
    );
  }
  
  async createEnquiryResponse(response: InsertEnquiryResponse): Promise<EnquiryResponse> {
    const id = this.currentEnquiryResponseIds++;
    const now = new Date();
    const newResponse: EnquiryResponse = {
      ...response,
      id,
      respondedAt: now,
      respondedByUserId: response.respondedByUserId || null
    };
    this.enquiryResponsesData.set(id, newResponse);
    
    // Update enquiry status
    const enquiry = this.enquiriesData.get(response.enquiryId);
    if (enquiry) {
      const updatedEnquiry = {
        ...enquiry,
        status: "responded" as const,
        updatedAt: now
      };
      this.enquiriesData.set(response.enquiryId, updatedEnquiry);
    }
    
    return newResponse;
  }

  // Initialize with sample data
  private initSampleData() {
    // Sample destinations
    const destinations: InsertDestination[] = [
      {
        name: "Caribbean",
        description: "Explore crystal-clear waters, white sandy beaches, and vibrant island cultures.",
        imageUrl: "https://images.unsplash.com/photo-1590523741831-ab7e8b8334b4",
        priceFrom: 599,
        rating: 4.5,
        cruiseCount: 12,
        durationRange: "7-10 Days"
      },
      {
        name: "Mediterranean",
        description: "Visit ancient ruins, coastal villages, and enjoy delicious cuisine across Europe.",
        imageUrl: "https://images.unsplash.com/photo-1602867741746-6df80f40c267",
        priceFrom: 899,
        rating: 5.0,
        cruiseCount: 15,
        durationRange: "10-14 Days"
      },
      {
        name: "Alaska",
        description: "Experience breathtaking glaciers, wildlife sightings, and magnificent landscapes.",
        imageUrl: "https://images.unsplash.com/photo-1473181488821-2d23949a045a",
        priceFrom: 799,
        rating: 4.5,
        cruiseCount: 8,
        durationRange: "7-14 Days"
      },
      {
        name: "Europe",
        description: "Discover historic cities, cultural landmarks, and beautiful countryside.",
        imageUrl: "https://images.unsplash.com/photo-1499856871958-5b9627545d1a",
        priceFrom: 999,
        rating: 4.8,
        cruiseCount: 10,
        durationRange: "10-14 Days"
      },
      {
        name: "Asia",
        description: "Experience diverse cultures, ancient temples, and exotic cuisine.",
        imageUrl: "https://images.unsplash.com/photo-1540959733332-eab4deabeeaf",
        priceFrom: 1099,
        rating: 4.7,
        cruiseCount: 6,
        durationRange: "12-18 Days"
      },
      {
        name: "Australia",
        description: "Explore the Great Barrier Reef, scenic coastlines, and vibrant cities.",
        imageUrl: "https://images.unsplash.com/photo-1523482580672-f109ba8cb9be",
        priceFrom: 1299,
        rating: 4.6,
        cruiseCount: 5,
        durationRange: "10-16 Days"
      }
    ];
    
    destinations.forEach(destination => {
      this.createDestination(destination);
    });

    // Sample cruises
    const cruises: InsertCruise[] = [
      {
        title: "Caribbean Paradise",
        description: "7-Night Western Caribbean & Perfect Day",
        destinationId: 1, // Caribbean
        imageUrl: "https://images.unsplash.com/photo-1548574505-5e239809ee19",
        departureFrom: "Miami, FL",
        duration: 7,
        pricePerPerson: 899,
        originalPrice: 1199,
        cabinType: "Ocean View Stateroom",
        inclusions: "All meals, Entertainment, Port charges",
        isBestSeller: true,
        isNewItinerary: false,
        rating: 4.5,
        availablePackages: ["Premium Dining Package", "$200 Onboard Credit"]
      },
      {
        title: "Greek Isles Explorer",
        description: "10-Night Greek Isles & Mediterranean Journey",
        destinationId: 2, // Mediterranean
        imageUrl: "https://images.unsplash.com/photo-1612456144614-8f2ebcc7bb40",
        departureFrom: "Rome, Italy",
        duration: 10,
        pricePerPerson: 1499,
        originalPrice: 1799,
        cabinType: "Balcony Stateroom",
        inclusions: "All meals, Entertainment, Port charges",
        isBestSeller: false,
        isNewItinerary: true,
        rating: 5.0,
        availablePackages: ["Specialty Dining (3 meals)", "Shore Excursion Credit", "Drink Package"]
      },
      {
        title: "Alaskan Adventure",
        description: "7-Night Glacier Experience",
        destinationId: 3, // Alaska
        imageUrl: "https://images.unsplash.com/photo-1531253450048-8e5e6a1d5db3",
        departureFrom: "Seattle, WA",
        duration: 7,
        pricePerPerson: 1099,
        originalPrice: 1399,
        cabinType: "Balcony Stateroom",
        inclusions: "All meals, Entertainment, Port charges",
        isBestSeller: true,
        isNewItinerary: false,
        rating: 4.7,
        availablePackages: ["Wildlife Excursion Package", "Premium Beverage Package"]
      },
      {
        title: "European Capitals",
        description: "12-Night Tour of Historic Cities",
        destinationId: 4, // Europe
        imageUrl: "https://images.unsplash.com/photo-1502920514313-52581002a659",
        departureFrom: "Southampton, UK",
        duration: 12,
        pricePerPerson: 1799,
        originalPrice: 2199,
        cabinType: "Deluxe Balcony",
        inclusions: "All meals, Entertainment, Port charges",
        isBestSeller: false,
        isNewItinerary: true,
        rating: 4.8,
        availablePackages: ["City Tours Bundle", "Fine Dining Experience"]
      }
    ];
    
    cruises.forEach(cruise => {
      this.createCruise(cruise);
    });

    // Sample amenities
    const amenities: InsertAmenity[] = [
      {
        name: "Gourmet Dining",
        description: "Savor exquisite cuisine prepared by world-class chefs in our specialty restaurants, with dishes inspired by global destinations.",
        imageUrl: "https://images.unsplash.com/photo-1593069567131-53a0614df2ea"
      },
      {
        name: "World-Class Entertainment",
        description: "Enjoy Broadway-style shows, live music, comedy performances, and themed parties throughout your cruise vacation.",
        imageUrl: "https://images.unsplash.com/photo-1591456983933-0cda86bbfec9"
      },
      {
        name: "Rejuvenating Spa",
        description: "Relax and refresh with our comprehensive spa treatments, thermal suites, and expert therapists for the ultimate relaxation.",
        imageUrl: "https://images.unsplash.com/photo-1610641818989-575305921886"
      },
      {
        name: "Adventure Activities",
        description: "Experience thrilling rock climbing walls, water slides, zip lines and more for adrenaline seekers of all ages.",
        imageUrl: "https://images.unsplash.com/photo-1566438480900-0609be27a4be"
      },
      {
        name: "Family-Friendly Zones",
        description: "Dedicated areas for children and teens with age-appropriate activities, games, and supervised programs.",
        imageUrl: "https://images.unsplash.com/photo-1596178065887-1198b6148b2b"
      },
      {
        name: "Luxury Shopping",
        description: "Browse high-end boutiques and duty-free shops featuring designer brands, jewelry, and exclusive souvenirs.",
        imageUrl: "https://images.unsplash.com/photo-1607083206968-13611e3d76db"
      }
    ];
    
    amenities.forEach(amenity => {
      this.createAmenity(amenity);
    });

    // Sample testimonials
    const testimonials: InsertTestimonial[] = [
      {
        name: "Robert J.",
        cruiseName: "Caribbean Paradise Cruise",
        comment: "Our Caribbean cruise exceeded all expectations. The staff was incredible, the food was amazing, and the excursions were unforgettable. Already planning our next trip!",
        rating: 5,
        avatarUrl: "https://images.unsplash.com/photo-1492562080023-ab3db95bfbce"
      },
      {
        name: "Jennifer M.",
        cruiseName: "Greek Isles Explorer",
        comment: "The Mediterranean cruise was the perfect family vacation. My kids loved the onboard activities, and my husband and I enjoyed the entertainment and shore excursions. Truly memorable!",
        rating: 5,
        avatarUrl: "https://images.unsplash.com/photo-1487412720507-e7ab37603c6f"
      },
      {
        name: "Lisa & David T.",
        cruiseName: "Alaska Adventure",
        comment: "As first-time cruisers, we were amazed by how smooth the entire experience was. The booking process was easy, and the onboard service was top-notch. Definitely recommend OceanView!",
        rating: 4,
        avatarUrl: "https://images.unsplash.com/photo-1534528741775-53994a69daeb"
      }
    ];
    
    testimonials.forEach(testimonial => {
      this.createTestimonial(testimonial);
    });
  }
}

import { DatabaseStorage } from "./database-storage";

// Export an instance of DatabaseStorage instead of MemStorage
export const storage = new DatabaseStorage();
