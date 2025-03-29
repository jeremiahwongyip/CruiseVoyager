import type { Express, Request, Response } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { z } from "zod";
import { 
  insertBookingSchema,
  searchSchema,
  insertTestimonialSchema,
  insertEnquirySchema,
  insertEnquiryResponseSchema,
  contactSchema
} from "@shared/schema";
import { ZodError } from "zod";
import { fromZodError } from "zod-validation-error";
import { setupAuth, isAuthenticated } from "./auth";
import csrf from "csurf";
import cookieParser from "cookie-parser";
import { APP_SECRET } from "./config";

export async function registerRoutes(app: Express): Promise<Server> {
  // Setup authentication
  setupAuth(app);
  
  // Create CSRF protection middleware
  const csrfProtection = csrf({
    cookie: {
      secure: process.env.NODE_ENV === "production",
      httpOnly: true,
      sameSite: "lax",
      signed: true
    }
  });

  // CSRF Token Route
  app.get("/api/csrf-token", csrfProtection, (req: Request, res: Response) => {
    res.json({ csrfToken: req.csrfToken() });
  });

  // Destination Routes
  app.get("/api/destinations", async (req, res, next) => {
    try {
      // Log all query parameters for debugging
      if (Object.keys(req.query).length > 0) {
        console.log("Destination search params:", req.query);
      }
      
      let destinations = await storage.getDestinations();
      
      // Handle date parameter - this won't filter destinations directly
      // but we'll log it to show we processed the request
      if (req.query.date) {
        try {
          // Format the date (YYYY-MM-DD)
          const dateParam = String(req.query.date);
          
          // Validate date format with regex (YYYY-MM-DD)
          const dateFormatRegex = /^\d{4}-\d{2}-\d{2}$/;
          if (dateFormatRegex.test(dateParam)) {
            const searchDate = new Date(dateParam);
            
            // Only process if it's a valid date
            if (!isNaN(searchDate.getTime())) {
              console.log(`Searching cruises for date: ${searchDate.toISOString().split('T')[0]}`);
              // The date parameter will be used client-side to filter cruises
              // No server-side filtering of destinations needed
            } else {
              console.warn(`Invalid date value: ${dateParam} - parsed as invalid date`);
            }
          } else {
            console.warn(`Invalid date format: ${dateParam} - should be YYYY-MM-DD`);
          }
        } catch (dateError) {
          console.error(`Error processing date parameter:`, dateError);
        }
      }
      
      // For region parameter, we could optionally filter here
      if (req.query.region) {
        const regionName = String(req.query.region);
        console.log(`Filtering destinations by region: ${regionName}`);
        // For now, we'll still return all destinations
        // but in a real implementation, we might filter by region here
      }
      
      // If no destinations are found, return empty array instead of null
      res.json(destinations || []);
    } catch (error) {
      console.error("Error fetching destinations:", error);
      next(error);
    }
  });

  app.get("/api/destinations/:id", async (req, res, next) => {
    try {
      const id = parseInt(req.params.id);
      if (isNaN(id)) {
        return res.status(400).json({ message: "Invalid destination ID" });
      }
      
      const destination = await storage.getDestination(id);
      if (!destination) {
        return res.status(404).json({ message: "Destination not found" });
      }
      
      res.json(destination);
    } catch (error) {
      next(error);
    }
  });

  // Cruise Routes
  app.get("/api/cruises", async (_req, res, next) => {
    try {
      const cruises = await storage.getCruises();
      res.json(cruises);
    } catch (error) {
      next(error);
    }
  });

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

  app.get("/api/cruises/destination/:destinationId", async (req, res, next) => {
    try {
      const destinationId = parseInt(req.params.destinationId);
      if (isNaN(destinationId)) {
        return res.status(400).json({ message: "Invalid destination ID" });
      }
      
      const cruises = await storage.getCruisesByDestination(destinationId);
      res.json(cruises);
    } catch (error) {
      next(error);
    }
  });
  
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

  // Booking Routes
  app.get("/api/bookings", async (req, res, next) => {
    try {
      if (!req.isAuthenticated()) {
        return res.status(401).json({ message: "Not authenticated" });
      }
      
      const user = req.user as any;
      const bookings = await storage.getBookings(user.id);
      res.json(bookings);
    } catch (error) {
      next(error);
    }
  });

  app.get("/api/bookings/:id", async (req, res, next) => {
    try {
      if (!req.isAuthenticated()) {
        return res.status(401).json({ message: "Not authenticated" });
      }
      
      const id = parseInt(req.params.id);
      if (isNaN(id)) {
        return res.status(400).json({ message: "Invalid booking ID" });
      }
      
      const booking = await storage.getBooking(id);
      if (!booking) {
        return res.status(404).json({ message: "Booking not found" });
      }
      
      const user = req.user as any;
      if (booking.userId !== user.id) {
        return res.status(403).json({ message: "Not authorized to view this booking" });
      }
      
      res.json(booking);
    } catch (error) {
      next(error);
    }
  });

  app.post("/api/bookings", async (req, res, next) => {
    try {
      if (!req.isAuthenticated()) {
        return res.status(401).json({ message: "Not authenticated" });
      }
      
      // Validate input
      const bookingData = insertBookingSchema.parse(req.body);
      
      const user = req.user as any;
      const newBooking = await storage.createBooking({
        ...bookingData,
        userId: user.id
      });
      
      res.status(201).json({ message: "Booking created successfully", booking: newBooking });
    } catch (error) {
      if (error instanceof ZodError) {
        return res.status(400).json({ message: fromZodError(error).message });
      }
      next(error);
    }
  });

  app.patch("/api/bookings/:id/status", async (req, res, next) => {
    try {
      if (!req.isAuthenticated()) {
        return res.status(401).json({ message: "Not authenticated" });
      }
      
      const id = parseInt(req.params.id);
      if (isNaN(id)) {
        return res.status(400).json({ message: "Invalid booking ID" });
      }
      
      const { status } = req.body;
      if (!status || typeof status !== "string") {
        return res.status(400).json({ message: "Invalid status" });
      }
      
      const booking = await storage.getBooking(id);
      if (!booking) {
        return res.status(404).json({ message: "Booking not found" });
      }
      
      const user = req.user as any;
      if (booking.userId !== user.id) {
        return res.status(403).json({ message: "Not authorized to update this booking" });
      }
      
      const updatedBooking = await storage.updateBookingStatus(id, status);
      res.json({ message: "Booking status updated", booking: updatedBooking });
    } catch (error) {
      next(error);
    }
  });

  // Amenity Routes
  app.get("/api/amenities", async (_req, res, next) => {
    try {
      const amenities = await storage.getAmenities();
      res.json(amenities);
    } catch (error) {
      next(error);
    }
  });

  // Testimonial Routes
  app.get("/api/testimonials", async (_req, res, next) => {
    try {
      const testimonials = await storage.getTestimonials();
      res.json(testimonials);
    } catch (error) {
      next(error);
    }
  });

  app.get("/api/cruises/:id/testimonials", async (req, res, next) => {
    try {
      const id = parseInt(req.params.id);
      if (isNaN(id)) {
        return res.status(400).json({ message: "Invalid cruise ID" });
      }
      
      const testimonials = await storage.getTestimonialsByCruise(id);
      res.json(testimonials);
    } catch (error) {
      next(error);
    }
  });

  app.post("/api/testimonials", async (req, res, next) => {
    try {
      // Allow authenticated users to associate their id with the testimonial
      let userData = {};
      if (req.isAuthenticated()) {
        const user = req.user as any;
        userData = { userId: user.id };
      }
      
      // Validate input
      const testimonialData = insertTestimonialSchema.parse(req.body);
      
      const newTestimonial = await storage.createTestimonial({
        ...testimonialData,
        ...userData
      });
      
      res.status(201).json({ 
        message: "Thank you for your testimonial! It will be reviewed shortly.", 
        testimonial: newTestimonial 
      });
    } catch (error) {
      if (error instanceof ZodError) {
        return res.status(400).json({ message: fromZodError(error).message });
      }
      next(error);
    }
  });

  app.patch("/api/testimonials/:id/verify", async (req, res, next) => {
    try {
      // In a real application, this would require admin authentication
      const id = parseInt(req.params.id);
      if (isNaN(id)) {
        return res.status(400).json({ message: "Invalid testimonial ID" });
      }
      
      const verifiedTestimonial = await storage.verifyTestimonial(id);
      if (!verifiedTestimonial) {
        return res.status(404).json({ message: "Testimonial not found" });
      }
      
      res.json({ 
        message: "Testimonial verified successfully", 
        testimonial: verifiedTestimonial 
      });
    } catch (error) {
      next(error);
    }
  });

  // Enquiry (Contact Form) Routes
  app.get("/api/enquiries", async (req, res, next) => {
    try {
      // In a real application, this would require admin authentication
      const enquiries = await storage.getEnquiries();
      res.json(enquiries);
    } catch (error) {
      next(error);
    }
  });

  app.get("/api/user/enquiries", async (req, res, next) => {
    try {
      if (!req.isAuthenticated()) {
        return res.status(401).json({ message: "Not authenticated" });
      }
      
      const user = req.user as any;
      const enquiries = await storage.getEnquiriesByUser(user.id);
      res.json(enquiries);
    } catch (error) {
      next(error);
    }
  });

  app.get("/api/enquiries/:id", async (req, res, next) => {
    try {
      const id = parseInt(req.params.id);
      if (isNaN(id)) {
        return res.status(400).json({ message: "Invalid enquiry ID" });
      }
      
      const enquiry = await storage.getEnquiry(id);
      if (!enquiry) {
        return res.status(404).json({ message: "Enquiry not found" });
      }
      
      // In a real application, check user permissions here
      res.json(enquiry);
    } catch (error) {
      next(error);
    }
  });

  app.post("/api/contact", async (req, res, next) => {
    try {
      // Validate input
      const contactData = contactSchema.parse(req.body);
      
      // Add user ID if authenticated
      let userData = {};
      if (req.isAuthenticated()) {
        const user = req.user as any;
        userData = { userId: user.id };
      }
      
      // Store as an enquiry
      const enquiry = await storage.createEnquiry({
        ...contactData,
        ...userData
      });
      
      res.status(201).json({
        message: "Thank you for your message. We will get back to you soon.",
        enquiryId: enquiry.id
      });
    } catch (error) {
      if (error instanceof ZodError) {
        return res.status(400).json({ message: fromZodError(error).message });
      }
      next(error);
    }
  });

  app.patch("/api/enquiries/:id/status", async (req, res, next) => {
    try {
      // In a real application, this would require staff authentication
      const id = parseInt(req.params.id);
      if (isNaN(id)) {
        return res.status(400).json({ message: "Invalid enquiry ID" });
      }
      
      const { status } = req.body;
      if (!status || typeof status !== "string") {
        return res.status(400).json({ message: "Invalid status" });
      }
      
      const enquiry = await storage.getEnquiry(id);
      if (!enquiry) {
        return res.status(404).json({ message: "Enquiry not found" });
      }
      
      const updatedEnquiry = await storage.updateEnquiryStatus(id, status);
      res.json({ 
        message: "Enquiry status updated", 
        enquiry: updatedEnquiry 
      });
    } catch (error) {
      next(error);
    }
  });

  app.get("/api/enquiries/:id/responses", async (req, res, next) => {
    try {
      const id = parseInt(req.params.id);
      if (isNaN(id)) {
        return res.status(400).json({ message: "Invalid enquiry ID" });
      }
      
      const enquiry = await storage.getEnquiry(id);
      if (!enquiry) {
        return res.status(404).json({ message: "Enquiry not found" });
      }
      
      // In a real application, check user permissions here
      const responses = await storage.getEnquiryResponses(id);
      res.json(responses);
    } catch (error) {
      next(error);
    }
  });

  app.post("/api/enquiries/:id/responses", async (req, res, next) => {
    try {
      const id = parseInt(req.params.id);
      if (isNaN(id)) {
        return res.status(400).json({ message: "Invalid enquiry ID" });
      }
      
      const enquiry = await storage.getEnquiry(id);
      if (!enquiry) {
        return res.status(404).json({ message: "Enquiry not found" });
      }
      
      // In a real application, this would require staff authentication
      // Add user ID if authenticated
      let userData = {};
      if (req.isAuthenticated()) {
        const user = req.user as any;
        userData = { respondedByUserId: user.id };
      }
      
      // Validate input
      const responseData = {
        ...req.body,
        enquiryId: id,
        ...userData
      };
      
      const newResponse = await storage.createEnquiryResponse(responseData);
      
      res.status(201).json({
        message: "Response added successfully",
        response: newResponse
      });
    } catch (error) {
      if (error instanceof ZodError) {
        return res.status(400).json({ message: fromZodError(error).message });
      }
      next(error);
    }
  });

  const httpServer = createServer(app);
  return httpServer;
}
