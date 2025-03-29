import { useState } from 'react';
import { useParams, useLocation } from 'wouter';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { apiRequest } from '@/lib/queryClient';
import { useAuth } from '@/hooks/use-auth';
import { useToast } from '@/hooks/use-toast';
import { Cruise } from '@shared/schema';
import { Form, FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { AlertCircle, Calendar, Check, CreditCard, Loader2, MapPin, Ship, User, Users } from 'lucide-react';

// Guest details schema
const guestSchema = z.object({
  firstName: z.string().min(1, 'First name is required'),
  lastName: z.string().min(1, 'Last name is required'),
  dateOfBirth: z.string().min(1, 'Date of birth is required'),
  nationality: z.string().min(1, 'Nationality is required'),
  passportNumber: z.string().min(1, 'Passport number is required'),
  passportExpiry: z.string().min(1, 'Passport expiry date is required'),
});

// Payment schema
const paymentSchema = z.object({
  cardNumber: z.string().min(16, 'Card number must be at least 16 digits').max(16, 'Card number must be at most 16 digits'),
  cardName: z.string().min(1, 'Cardholder name is required'),
  expiryDate: z.string().min(5, 'Expiry date is required').max(5, 'Invalid expiry date'),
  cvv: z.string().min(3, 'CVV must be at least 3 digits').max(4, 'CVV must be at most 4 digits'),
  billingAddress: z.string().min(1, 'Billing address is required'),
  city: z.string().min(1, 'City is required'),
  zipCode: z.string().min(1, 'Zip code is required'),
  country: z.string().min(1, 'Country is required'),
});

// Booking schema
const bookingSchema = z.object({
  cruiseId: z.number(),
  departureDate: z.string().min(1, 'Departure date is required'),
  numberOfGuests: z.number().min(1, 'Number of guests is required'),
  cabinType: z.string().min(1, 'Cabin type is required'),
  totalPrice: z.number().min(1, 'Total price is required'),
  guestDetails: z.array(guestSchema),
  paymentDetails: paymentSchema,
});

type BookingFormData = Omit<z.infer<typeof bookingSchema>, 'guestDetails' | 'paymentDetails'>;
type GuestFormData = z.infer<typeof guestSchema>;
type PaymentFormData = z.infer<typeof paymentSchema>;

const BookingPage = () => {
  const { cruiseId } = useParams<{ cruiseId: string }>();
  const [_, navigate] = useLocation();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  
  // Get URL params for cabin type and price
  const searchParams = new URLSearchParams(location.search);
  const cabinTypeFromUrl = searchParams.get('cabin');
  const priceFromUrl = searchParams.get('price');
  
  // Form state
  const [activeStep, setActiveStep] = useState<'details' | 'guests' | 'payment' | 'review'>('details');
  const [bookingDetails, setBookingDetails] = useState<BookingFormData>({
    cruiseId: parseInt(cruiseId),
    departureDate: '',
    numberOfGuests: 2,
    cabinType: cabinTypeFromUrl || '',
    totalPrice: priceFromUrl ? parseInt(priceFromUrl) * 2 : 0, // Default to 2 guests
  });
  const [guestDetails, setGuestDetails] = useState<GuestFormData[]>([]);
  const [paymentDetails, setPaymentDetails] = useState<PaymentFormData | null>(null);
  
  // Fetch cruise details
  const { data: cruiseData, isLoading, error } = useQuery<Cruise>({
    queryKey: [`/api/cruises/${cruiseId}`],
    enabled: !!cruiseId,
  });
  
  // Properly typed cruise data
  const cruise = cruiseData as Cruise;
  
  // Use authentication hook
  const { user, isLoading: isLoadingAuth } = useAuth();
  
  // Forms
  const detailsForm = useForm<BookingFormData>({
    resolver: zodResolver(bookingSchema.pick({
      departureDate: true,
      numberOfGuests: true,
      cabinType: true,
    })),
    defaultValues: {
      departureDate: bookingDetails.departureDate,
      numberOfGuests: bookingDetails.numberOfGuests,
      cabinType: bookingDetails.cabinType || (cruise ? cruise.cabinType : ''),
    },
  });
  
  const guestForm = useForm<GuestFormData>({
    resolver: zodResolver(guestSchema),
    defaultValues: {
      firstName: '',
      lastName: '',
      dateOfBirth: '',
      nationality: '',
      passportNumber: '',
      passportExpiry: '',
    },
  });
  
  const paymentForm = useForm<PaymentFormData>({
    resolver: zodResolver(paymentSchema),
    defaultValues: {
      cardNumber: '',
      cardName: '',
      expiryDate: '',
      cvv: '',
      billingAddress: '',
      city: '',
      zipCode: '',
      country: '',
    },
  });
  
  // Create booking mutation
  const bookingMutation = useMutation({
    mutationFn: async (data: any) => {
      const response = await apiRequest('POST', '/api/bookings', data);
      return response.json();
    },
    onSuccess: (data) => {
      toast({
        title: "Booking successful!",
        description: `Your booking has been confirmed. Booking reference: #${data.booking.id}`,
        variant: "success",
      });
      
      // Redirect to profile page
      navigate('/profile');
    },
    onError: (error: any) => {
      toast({
        title: "Booking failed",
        description: error.message || "There was an error processing your booking. Please try again.",
        variant: "destructive",
      });
      setActiveStep('review');
    },
  });
  
  // Handle details form submission
  const onDetailsSubmit = (data: any) => {
    const totalPrice = cruise.pricePerPerson * data.numberOfGuests;
    
    setBookingDetails({
      ...bookingDetails,
      departureDate: data.departureDate,
      numberOfGuests: data.numberOfGuests,
      cabinType: data.cabinType,
      totalPrice: totalPrice,
    });
    
    // Initialize guest forms array based on number of guests
    const guests = Array(data.numberOfGuests).fill(null).map(() => ({
      firstName: '',
      lastName: '',
      dateOfBirth: '',
      nationality: '',
      passportNumber: '',
      passportExpiry: '',
    }));
    
    setGuestDetails(guests);
    setActiveStep('guests');
  };
  
  // Handle guest form submission for a specific guest
  const onGuestSubmit = (data: GuestFormData, guestIndex: number) => {
    const updatedGuests = [...guestDetails];
    updatedGuests[guestIndex] = data;
    setGuestDetails(updatedGuests);
    
    // If all guests are filled out, move to payment
    if (updatedGuests.every(guest => 
      guest.firstName && 
      guest.lastName && 
      guest.dateOfBirth && 
      guest.nationality && 
      guest.passportNumber && 
      guest.passportExpiry
    )) {
      setActiveStep('payment');
    }
  };
  
  // Handle payment form submission
  const onPaymentSubmit = (data: PaymentFormData) => {
    setPaymentDetails(data);
    setActiveStep('review');
  };
  
  // Final booking submission
  const onBookingSubmit = () => {
    if (!user) {
      toast({
        title: "Authentication required",
        description: "Please log in to complete your booking.",
        variant: "destructive",
      });
      navigate('/auth');
      return;
    }
    
    const finalBookingData = {
      cruiseId: parseInt(cruiseId),
      departureDate: bookingDetails.departureDate,
      totalPrice: bookingDetails.totalPrice,
      numberOfGuests: bookingDetails.numberOfGuests,
      cabinType: bookingDetails.cabinType,
      guestDetails: guestDetails,
      status: 'confirmed',
    };
    
    bookingMutation.mutate(finalBookingData);
  };
  
  // Note: Using ProtectedRoute component means we don't need this check anymore
  // It's kept here as an additional security measure
  if (!isLoadingAuth && !user) {
    toast({
      title: "Authentication required",
      description: "Please log in to book a cruise.",
      variant: "destructive",
    });
    navigate('/auth');
    return null;
  }
  
  // Loading states
  if (isLoading) {
    return (
      <div className="container mx-auto py-12 px-4">
        <div className="text-center">
          <Loader2 className="h-8 w-8 animate-spin mx-auto mb-4" />
          <h1 className="text-2xl font-bold">Loading booking information...</h1>
        </div>
      </div>
    );
  }
  
  if (error || !cruise) {
    return (
      <div className="container mx-auto py-12 px-4">
        <div className="text-center">
          <AlertCircle className="h-8 w-8 mx-auto mb-4 text-red-500" />
          <h1 className="text-2xl font-bold">Cruise Not Found</h1>
          <p className="mt-2">The cruise you are trying to book is not available.</p>
          <Button 
            className="mt-4 bg-[#1a75bc] hover:bg-[#0d4677]"
            onClick={() => navigate('/destinations')}
          >
            Browse All Cruises
          </Button>
        </div>
      </div>
    );
  }
  
  return (
    <div className="bg-[#f8f9fb] min-h-screen py-12">
      <div className="container mx-auto px-4">
        <h1 className="text-3xl font-montserrat font-bold text-[#0d4677] mb-6 text-center">Book Your Cruise</h1>
        
        {/* Booking Steps */}
        <div className="max-w-3xl mx-auto mb-10">
          <div className="flex justify-between relative">
            <div className="absolute top-1/2 left-0 right-0 h-1 bg-gray-200 -translate-y-1/2 z-0"></div>
            
            <div className={`relative z-10 flex flex-col items-center ${activeStep === 'details' ? 'text-[#1a75bc]' : 'text-gray-500'}`}>
              <div className={`w-10 h-10 rounded-full ${activeStep === 'details' ? 'bg-[#1a75bc] text-white' : 'bg-white text-gray-500 border border-gray-300'} flex items-center justify-center mb-2`}>
                <Ship className="h-5 w-5" />
              </div>
              <div className="text-sm font-medium">Details</div>
            </div>
            
            <div className={`relative z-10 flex flex-col items-center ${activeStep === 'guests' ? 'text-[#1a75bc]' : 'text-gray-500'}`}>
              <div className={`w-10 h-10 rounded-full ${activeStep === 'guests' ? 'bg-[#1a75bc] text-white' : 'bg-white text-gray-500 border border-gray-300'} flex items-center justify-center mb-2`}>
                <Users className="h-5 w-5" />
              </div>
              <div className="text-sm font-medium">Guests</div>
            </div>
            
            <div className={`relative z-10 flex flex-col items-center ${activeStep === 'payment' ? 'text-[#1a75bc]' : 'text-gray-500'}`}>
              <div className={`w-10 h-10 rounded-full ${activeStep === 'payment' ? 'bg-[#1a75bc] text-white' : 'bg-white text-gray-500 border border-gray-300'} flex items-center justify-center mb-2`}>
                <CreditCard className="h-5 w-5" />
              </div>
              <div className="text-sm font-medium">Payment</div>
            </div>
            
            <div className={`relative z-10 flex flex-col items-center ${activeStep === 'review' ? 'text-[#1a75bc]' : 'text-gray-500'}`}>
              <div className={`w-10 h-10 rounded-full ${activeStep === 'review' ? 'bg-[#1a75bc] text-white' : 'bg-white text-gray-500 border border-gray-300'} flex items-center justify-center mb-2`}>
                <Check className="h-5 w-5" />
              </div>
              <div className="text-sm font-medium">Review</div>
            </div>
          </div>
        </div>
        
        {/* Main Content */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 max-w-5xl mx-auto">
          {/* Left Column - Forms */}
          <div className="lg:col-span-2">
            {/* Booking Details Step */}
            {activeStep === 'details' && (
              <Card>
                <CardHeader>
                  <CardTitle>Cruise & Cabin Selection</CardTitle>
                  <CardDescription>Choose your departure date, number of guests, and cabin type</CardDescription>
                </CardHeader>
                <CardContent>
                  <Form {...detailsForm}>
                    <form onSubmit={detailsForm.handleSubmit(onDetailsSubmit)} className="space-y-6">
                      <FormField
                        control={detailsForm.control}
                        name="departureDate"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Departure Date</FormLabel>
                            <FormControl>
                              <Select 
                                onValueChange={field.onChange} 
                                defaultValue={field.value}
                              >
                                <SelectTrigger>
                                  <SelectValue placeholder="Select departure date" />
                                </SelectTrigger>
                                <SelectContent>
                                  <SelectItem value="2023-12-18">Dec 18, 2023</SelectItem>
                                  <SelectItem value="2024-01-15">Jan 15, 2024</SelectItem>
                                  <SelectItem value="2024-02-12">Feb 12, 2024</SelectItem>
                                  <SelectItem value="2024-03-18">Mar 18, 2024</SelectItem>
                                </SelectContent>
                              </Select>
                            </FormControl>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                      
                      <FormField
                        control={detailsForm.control}
                        name="numberOfGuests"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Number of Guests</FormLabel>
                            <FormControl>
                              <Select 
                                onValueChange={(value) => field.onChange(parseInt(value))} 
                                defaultValue={field.value.toString()}
                              >
                                <SelectTrigger>
                                  <SelectValue placeholder="Select number of guests" />
                                </SelectTrigger>
                                <SelectContent>
                                  <SelectItem value="1">1 Guest</SelectItem>
                                  <SelectItem value="2">2 Guests</SelectItem>
                                  <SelectItem value="3">3 Guests</SelectItem>
                                  <SelectItem value="4">4 Guests</SelectItem>
                                  <SelectItem value="5">5 Guests</SelectItem>
                                </SelectContent>
                              </Select>
                            </FormControl>
                            <FormDescription>
                              Price per person: ${cruise.pricePerPerson}
                            </FormDescription>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                      
                      <FormField
                        control={detailsForm.control}
                        name="cabinType"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Cabin Type</FormLabel>
                            <FormControl>
                              <Select 
                                onValueChange={field.onChange} 
                                defaultValue={field.value}
                              >
                                <SelectTrigger>
                                  <SelectValue placeholder="Select cabin type" />
                                </SelectTrigger>
                                <SelectContent>
                                  <SelectItem value="Interior">Interior</SelectItem>
                                  <SelectItem value="Ocean View Stateroom">Ocean View</SelectItem>
                                  <SelectItem value="Balcony Stateroom">Balcony</SelectItem>
                                  <SelectItem value="Suite">Suite</SelectItem>
                                </SelectContent>
                              </Select>
                            </FormControl>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                      
                      <Button 
                        type="submit" 
                        className="w-full bg-[#1a75bc] hover:bg-[#0d4677]"
                      >
                        Continue to Guest Details
                      </Button>
                    </form>
                  </Form>
                </CardContent>
              </Card>
            )}
            
            {/* Guest Details Step */}
            {activeStep === 'guests' && (
              <Card>
                <CardHeader>
                  <CardTitle>Guest Information</CardTitle>
                  <CardDescription>Please provide details for all {bookingDetails.numberOfGuests} guest(s)</CardDescription>
                </CardHeader>
                <CardContent>
                  <Tabs defaultValue="guest1">
                    <TabsList className="grid grid-cols-4 mb-4">
                      {Array.from({ length: bookingDetails.numberOfGuests }).map((_, index) => (
                        <TabsTrigger key={index} value={`guest${index + 1}`} className="text-sm">
                          Guest {index + 1}
                        </TabsTrigger>
                      ))}
                    </TabsList>
                    
                    {Array.from({ length: bookingDetails.numberOfGuests }).map((_, index) => (
                      <TabsContent key={index} value={`guest${index + 1}`}>
                        <Form {...guestForm}>
                          <form 
                            onSubmit={guestForm.handleSubmit((data) => onGuestSubmit(data, index))} 
                            className="space-y-4"
                          >
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                              <FormField
                                control={guestForm.control}
                                name="firstName"
                                render={({ field }) => (
                                  <FormItem>
                                    <FormLabel>First Name</FormLabel>
                                    <FormControl>
                                      <Input placeholder="John" {...field} />
                                    </FormControl>
                                    <FormMessage />
                                  </FormItem>
                                )}
                              />
                              
                              <FormField
                                control={guestForm.control}
                                name="lastName"
                                render={({ field }) => (
                                  <FormItem>
                                    <FormLabel>Last Name</FormLabel>
                                    <FormControl>
                                      <Input placeholder="Doe" {...field} />
                                    </FormControl>
                                    <FormMessage />
                                  </FormItem>
                                )}
                              />
                            </div>
                            
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                              <FormField
                                control={guestForm.control}
                                name="dateOfBirth"
                                render={({ field }) => (
                                  <FormItem>
                                    <FormLabel>Date of Birth</FormLabel>
                                    <FormControl>
                                      <Input type="date" {...field} />
                                    </FormControl>
                                    <FormMessage />
                                  </FormItem>
                                )}
                              />
                              
                              <FormField
                                control={guestForm.control}
                                name="nationality"
                                render={({ field }) => (
                                  <FormItem>
                                    <FormLabel>Nationality</FormLabel>
                                    <FormControl>
                                      <Input placeholder="e.g. American" {...field} />
                                    </FormControl>
                                    <FormMessage />
                                  </FormItem>
                                )}
                              />
                            </div>
                            
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                              <FormField
                                control={guestForm.control}
                                name="passportNumber"
                                render={({ field }) => (
                                  <FormItem>
                                    <FormLabel>Passport Number</FormLabel>
                                    <FormControl>
                                      <Input placeholder="e.g. 123456789" {...field} />
                                    </FormControl>
                                    <FormMessage />
                                  </FormItem>
                                )}
                              />
                              
                              <FormField
                                control={guestForm.control}
                                name="passportExpiry"
                                render={({ field }) => (
                                  <FormItem>
                                    <FormLabel>Passport Expiry Date</FormLabel>
                                    <FormControl>
                                      <Input type="date" {...field} />
                                    </FormControl>
                                    <FormMessage />
                                  </FormItem>
                                )}
                              />
                            </div>
                            
                            <div className="flex justify-between mt-6">
                              <Button 
                                type="button" 
                                variant="outline"
                                onClick={() => setActiveStep('details')}
                              >
                                Back to Details
                              </Button>
                              
                              <Button 
                                type="submit" 
                                className="bg-[#1a75bc] hover:bg-[#0d4677]"
                              >
                                {index === bookingDetails.numberOfGuests - 1 ? "Continue to Payment" : `Save & Next Guest`}
                              </Button>
                            </div>
                          </form>
                        </Form>
                      </TabsContent>
                    ))}
                  </Tabs>
                </CardContent>
              </Card>
            )}
            
            {/* Payment Step */}
            {activeStep === 'payment' && (
              <Card>
                <CardHeader>
                  <CardTitle>Payment Information</CardTitle>
                  <CardDescription>Enter your payment details to complete the booking</CardDescription>
                </CardHeader>
                <CardContent>
                  <Form {...paymentForm}>
                    <form onSubmit={paymentForm.handleSubmit(onPaymentSubmit)} className="space-y-6">
                      <FormField
                        control={paymentForm.control}
                        name="cardNumber"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Card Number</FormLabel>
                            <FormControl>
                              <Input placeholder="1234 5678 9012 3456" {...field} />
                            </FormControl>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                      
                      <FormField
                        control={paymentForm.control}
                        name="cardName"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Cardholder Name</FormLabel>
                            <FormControl>
                              <Input placeholder="John Doe" {...field} />
                            </FormControl>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                      
                      <div className="grid grid-cols-2 gap-4">
                        <FormField
                          control={paymentForm.control}
                          name="expiryDate"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>Expiry Date (MM/YY)</FormLabel>
                              <FormControl>
                                <Input placeholder="01/25" {...field} />
                              </FormControl>
                              <FormMessage />
                            </FormItem>
                          )}
                        />
                        
                        <FormField
                          control={paymentForm.control}
                          name="cvv"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>CVV</FormLabel>
                              <FormControl>
                                <Input placeholder="123" {...field} />
                              </FormControl>
                              <FormMessage />
                            </FormItem>
                          )}
                        />
                      </div>
                      
                      <FormField
                        control={paymentForm.control}
                        name="billingAddress"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Billing Address</FormLabel>
                            <FormControl>
                              <Input placeholder="123 Main St" {...field} />
                            </FormControl>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                      
                      <div className="grid grid-cols-2 gap-4">
                        <FormField
                          control={paymentForm.control}
                          name="city"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>City</FormLabel>
                              <FormControl>
                                <Input placeholder="New York" {...field} />
                              </FormControl>
                              <FormMessage />
                            </FormItem>
                          )}
                        />
                        
                        <FormField
                          control={paymentForm.control}
                          name="zipCode"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>Zip Code</FormLabel>
                              <FormControl>
                                <Input placeholder="10001" {...field} />
                              </FormControl>
                              <FormMessage />
                            </FormItem>
                          )}
                        />
                      </div>
                      
                      <FormField
                        control={paymentForm.control}
                        name="country"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Country</FormLabel>
                            <FormControl>
                              <Input placeholder="United States" {...field} />
                            </FormControl>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                      
                      <div className="flex justify-between mt-6">
                        <Button 
                          type="button" 
                          variant="outline"
                          onClick={() => setActiveStep('guests')}
                        >
                          Back to Guest Details
                        </Button>
                        
                        <Button 
                          type="submit" 
                          className="bg-[#1a75bc] hover:bg-[#0d4677]"
                        >
                          Continue to Review
                        </Button>
                      </div>
                    </form>
                  </Form>
                </CardContent>
              </Card>
            )}
            
            {/* Review Step */}
            {activeStep === 'review' && (
              <Card>
                <CardHeader>
                  <CardTitle>Review & Confirm</CardTitle>
                  <CardDescription>Please review your booking details before confirming</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-6">
                    <div>
                      <h3 className="text-lg font-semibold mb-2">Cruise Details</h3>
                      <div className="bg-gray-50 p-4 rounded-lg space-y-2">
                        <div className="flex justify-between">
                          <span className="text-gray-600">Cruise:</span>
                          <span className="font-medium">{cruise.title}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-600">Departure Date:</span>
                          <span className="font-medium">{bookingDetails.departureDate}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-600">Duration:</span>
                          <span className="font-medium">{cruise.duration} Nights</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-600">Cabin Type:</span>
                          <span className="font-medium">{bookingDetails.cabinType}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-600">Number of Guests:</span>
                          <span className="font-medium">{bookingDetails.numberOfGuests}</span>
                        </div>
                      </div>
                    </div>
                    
                    <div>
                      <h3 className="text-lg font-semibold mb-2">Guest Information</h3>
                      <div className="bg-gray-50 p-4 rounded-lg space-y-4">
                        {guestDetails.map((guest, index) => (
                          <div key={index} className="pb-2 border-b border-gray-200 last:border-0 last:pb-0">
                            <h4 className="font-medium mb-1">Guest {index + 1}: {guest.firstName} {guest.lastName}</h4>
                            <div className="grid grid-cols-2 gap-2 text-sm">
                              <div>
                                <span className="text-gray-600">Date of Birth:</span> {guest.dateOfBirth}
                              </div>
                              <div>
                                <span className="text-gray-600">Nationality:</span> {guest.nationality}
                              </div>
                              <div>
                                <span className="text-gray-600">Passport:</span> {guest.passportNumber}
                              </div>
                              <div>
                                <span className="text-gray-600">Passport Expiry:</span> {guest.passportExpiry}
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                    
                    <div>
                      <h3 className="text-lg font-semibold mb-2">Payment Information</h3>
                      <div className="bg-gray-50 p-4 rounded-lg space-y-2">
                        <div className="flex justify-between">
                          <span className="text-gray-600">Card Number:</span>
                          <span className="font-medium">**** **** **** {paymentDetails?.cardNumber.slice(-4)}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-600">Cardholder:</span>
                          <span className="font-medium">{paymentDetails?.cardName}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-600">Billing Address:</span>
                          <span className="font-medium">{paymentDetails?.billingAddress}, {paymentDetails?.city}, {paymentDetails?.zipCode}</span>
                        </div>
                      </div>
                    </div>
                    
                    <div className="border-t border-gray-200 pt-4">
                      <div className="flex justify-between text-xl font-semibold">
                        <span>Total Price:</span>
                        <span>${bookingDetails.totalPrice}</span>
                      </div>
                      <p className="text-sm text-gray-600 mt-1">
                        Includes all taxes and fees.
                      </p>
                    </div>
                    
                    <div className="flex justify-between mt-6">
                      <Button 
                        type="button" 
                        variant="outline"
                        onClick={() => setActiveStep('payment')}
                      >
                        Back to Payment
                      </Button>
                      
                      <Button 
                        className="bg-[#ff7043] hover:bg-[#e65100]"
                        onClick={onBookingSubmit}
                        disabled={bookingMutation.isPending}
                      >
                        {bookingMutation.isPending ? (
                          <>
                            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                            Processing...
                          </>
                        ) : (
                          "Confirm & Pay"
                        )}
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            )}
          </div>
          
          {/* Right Column - Booking Summary */}
          <div>
            <Card className="sticky top-24">
              <CardHeader>
                <CardTitle>Booking Summary</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center">
                  <Ship className="h-5 w-5 mr-3 text-[#1a75bc]" />
                  <div>
                    <p className="font-medium">{cruise.title}</p>
                    <p className="text-sm text-gray-600">{cruise.duration} Nights</p>
                  </div>
                </div>
                
                <div className="flex items-center">
                  <MapPin className="h-5 w-5 mr-3 text-[#1a75bc]" />
                  <div>
                    <p className="font-medium">{cruise.departureFrom}</p>
                    <p className="text-sm text-gray-600">Departure Port</p>
                  </div>
                </div>
                
                {bookingDetails.departureDate && (
                  <div className="flex items-center">
                    <Calendar className="h-5 w-5 mr-3 text-[#1a75bc]" />
                    <div>
                      <p className="font-medium">{bookingDetails.departureDate}</p>
                      <p className="text-sm text-gray-600">Departure Date</p>
                    </div>
                  </div>
                )}
                
                {bookingDetails.cabinType && (
                  <div className="flex items-center">
                    <User className="h-5 w-5 mr-3 text-[#1a75bc]" />
                    <div>
                      <p className="font-medium">{bookingDetails.cabinType}</p>
                      <p className="text-sm text-gray-600">Cabin Type</p>
                    </div>
                  </div>
                )}
                
                <div className="flex items-center">
                  <Users className="h-5 w-5 mr-3 text-[#1a75bc]" />
                  <div>
                    <p className="font-medium">{bookingDetails.numberOfGuests} Guests</p>
                    <p className="text-sm text-gray-600">${cruise.pricePerPerson} per person</p>
                  </div>
                </div>
                
                <div className="border-t border-gray-200 pt-4 mt-4">
                  <div className="flex justify-between mb-2">
                    <span className="text-gray-600">Cruise Fare</span>
                    <span>${cruise.pricePerPerson * bookingDetails.numberOfGuests}</span>
                  </div>
                  <div className="flex justify-between mb-2">
                    <span className="text-gray-600">Taxes & Fees</span>
                    <span>Included</span>
                  </div>
                  <div className="flex justify-between font-semibold text-lg pt-2 border-t border-gray-200">
                    <span>Total</span>
                    <span>${bookingDetails.totalPrice || (cruise.pricePerPerson * bookingDetails.numberOfGuests)}</span>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </div>
  );
};

export default BookingPage;
