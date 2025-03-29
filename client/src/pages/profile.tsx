import { useEffect, useState } from 'react';
import { useLocation } from 'wouter';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Booking, Cruise } from '@shared/schema';
import { apiRequest } from '@/lib/queryClient';
import { useAuth } from '@/hooks/use-auth';
import { useToast } from '@/hooks/use-toast';
import { formatDate, formatCurrency } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Separator } from '@/components/ui/separator';
import { Loader2, User, Ship, Calendar, MapPin, CreditCard, Clock, Check, AlertCircle, LogOut } from 'lucide-react';

const BookingCard = ({ booking, cruise }: { booking: Booking, cruise?: Cruise }) => {
  const [_, navigate] = useLocation();
  const queryClient = useQueryClient();
  const { toast } = useToast();
  
  const cancelMutation = useMutation({
    mutationFn: async () => {
      return await apiRequest('PATCH', `/api/bookings/${booking.id}/status`, { status: 'cancelled' });
    },
    onSuccess: () => {
      toast({
        title: "Booking cancelled",
        description: "Your booking has been successfully cancelled.",
        variant: "success",
      });
      queryClient.invalidateQueries({ queryKey: ['/api/bookings'] });
    },
    onError: () => {
      toast({
        title: "Failed to cancel booking",
        description: "There was an error cancelling your booking. Please try again.",
        variant: "destructive",
      });
    },
  });
  
  const isPast = new Date(booking.departureDate) < new Date();
  const isCancelled = booking.status === 'cancelled';
  
  return (
    <Card className="mb-6">
      <CardHeader className="pb-3">
        <div className="flex flex-wrap justify-between items-start gap-2">
          <div>
            <CardTitle className="text-xl">{cruise?.title || 'Cruise Package'}</CardTitle>
            <CardDescription>Booking Reference: #{booking.id}</CardDescription>
          </div>
          <div className={`px-3 py-1 rounded-full text-sm font-medium ${
            isCancelled ? 'bg-red-100 text-red-800' : 
            isPast ? 'bg-gray-100 text-gray-800' : 
            'bg-green-100 text-green-800'
          }`}>
            {isCancelled ? 'Cancelled' : isPast ? 'Completed' : 'Confirmed'}
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
          <div className="flex items-start">
            <Calendar className="h-5 w-5 mr-2 text-[#1a75bc] mt-0.5" />
            <div>
              <p className="font-medium">Departure Date</p>
              <p className="text-gray-600">{formatDate(booking.departureDate)}</p>
            </div>
          </div>
          <div className="flex items-start">
            <MapPin className="h-5 w-5 mr-2 text-[#1a75bc] mt-0.5" />
            <div>
              <p className="font-medium">Port</p>
              <p className="text-gray-600">{cruise?.departureFrom || 'Departure Port'}</p>
            </div>
          </div>
          <div className="flex items-start">
            <Ship className="h-5 w-5 mr-2 text-[#1a75bc] mt-0.5" />
            <div>
              <p className="font-medium">Cabin Type</p>
              <p className="text-gray-600">{booking.cabinType}</p>
            </div>
          </div>
          <div className="flex items-start">
            <User className="h-5 w-5 mr-2 text-[#1a75bc] mt-0.5" />
            <div>
              <p className="font-medium">Guests</p>
              <p className="text-gray-600">{booking.numberOfGuests} {booking.numberOfGuests === 1 ? 'Guest' : 'Guests'}</p>
            </div>
          </div>
        </div>
        <Separator className="my-4" />
        <div className="flex justify-between items-center">
          <div>
            <p className="font-medium">Total Paid</p>
            <p className="text-2xl font-bold text-[#0d4677]">{formatCurrency(booking.totalPrice)}</p>
          </div>
          {!isPast && !isCancelled && (
            <Button
              variant="outline"
              className="border-red-500 text-red-500 hover:bg-red-50"
              onClick={() => cancelMutation.mutate()}
              disabled={cancelMutation.isPending}
            >
              {cancelMutation.isPending ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Cancelling...
                </>
              ) : (
                "Cancel Booking"
              )}
            </Button>
          )}
        </div>
      </CardContent>
    </Card>
  );
};

const Profile = () => {
  const [_, navigate] = useLocation();
  const { user, isLoading: isLoadingAuth, logoutMutation } = useAuth();
  const { toast } = useToast();
  
  // Fetch bookings
  const { data: bookingsData, isLoading: isLoadingBookings } = useQuery({
    queryKey: ['/api/bookings'],
    enabled: !!user,
  });
  
  // Fetch cruises for bookings
  const { data: cruises, isLoading: isLoadingCruises } = useQuery({
    queryKey: ['/api/cruises'],
    enabled: !!bookingsData,
  });
  
  // If loading, show spinner
  if (isLoadingAuth || isLoadingBookings || isLoadingCruises) {
    return (
      <div className="container mx-auto p-6 py-16 flex items-center justify-center min-h-[50vh]">
        <div className="text-center">
          <Loader2 className="h-8 w-8 animate-spin mx-auto mb-4 text-[#1a75bc]" />
          <h2 className="text-2xl font-bold text-[#0d4677]">Loading profile...</h2>
        </div>
      </div>
    );
  }
  
  // Note: Since we're using ProtectedRoute, this component will only be rendered if a user exists
  if (!user) {
    return null; // Safety check
  }
  
  const bookings = bookingsData || [];
  
  // Explicitly type the bookings for TypeScript
  const typedBookings = Array.isArray(bookings) ? bookings as Booking[] : [];
  const typedCruises = Array.isArray(cruises) ? cruises as Cruise[] : [];

  // Filter bookings by status
  const upcomingBookings = typedBookings.filter(
    (booking) => 
      booking.status !== 'cancelled' && 
      new Date(booking.departureDate) >= new Date()
  );
  
  const pastBookings = typedBookings.filter(
    (booking) => 
      booking.status !== 'cancelled' && 
      new Date(booking.departureDate) < new Date()
  );
  
  const cancelledBookings = typedBookings.filter(
    (booking) => booking.status === 'cancelled'
  );
  
  // Get cruise details for a booking
  const getCruiseForBooking = (booking: Booking) => {
    return typedCruises.find((cruise) => cruise.id === booking.cruiseId);
  };
  
  return (
    <div className="container mx-auto p-6 py-16">
      <div className="mb-10">
        <div className="flex flex-wrap justify-between items-center gap-4 mb-6">
          <div>
            <h1 className="text-3xl font-bold text-[#0d4677]">My Profile</h1>
            <p className="text-gray-600">Welcome back, {user.firstName || user.username}</p>
          </div>
          <Button 
            variant="outline" 
            className="flex items-center gap-2"
            onClick={() => logoutMutation.mutate()}
            disabled={logoutMutation.isPending}
          >
            {logoutMutation.isPending ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                Logging out...
              </>
            ) : (
              <>
                <LogOut className="h-4 w-4" />
                Logout
              </>
            )}
          </Button>
        </div>
        
        <Card>
          <CardHeader>
            <CardTitle>Personal Information</CardTitle>
          </CardHeader>
          <CardContent className="grid gap-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <p className="text-sm font-medium text-gray-500">Username</p>
                <p className="text-lg">{user.username}</p>
              </div>
              <div>
                <p className="text-sm font-medium text-gray-500">Email</p>
                <p className="text-lg">{user.email}</p>
              </div>
              <div>
                <p className="text-sm font-medium text-gray-500">First Name</p>
                <p className="text-lg">{user.firstName || 'Not provided'}</p>
              </div>
              <div>
                <p className="text-sm font-medium text-gray-500">Last Name</p>
                <p className="text-lg">{user.lastName || 'Not provided'}</p>
              </div>
            </div>
          </CardContent>
          <CardFooter>
            <Button variant="outline">Edit Profile</Button>
          </CardFooter>
        </Card>
      </div>
      
      <div>
        <h2 className="text-2xl font-bold text-[#0d4677] mb-6">My Bookings</h2>
        
        <Tabs defaultValue="upcoming" className="mb-6">
          <TabsList className="mb-6">
            <TabsTrigger value="upcoming" className="relative">
              Upcoming
              {upcomingBookings.length > 0 && (
                <span className="absolute -top-2 -right-2 bg-[#1a75bc] text-white rounded-full w-5 h-5 flex items-center justify-center text-xs">
                  {upcomingBookings.length}
                </span>
              )}
            </TabsTrigger>
            <TabsTrigger value="past">Past</TabsTrigger>
            <TabsTrigger value="cancelled">Cancelled</TabsTrigger>
          </TabsList>
          
          <TabsContent value="upcoming">
            {upcomingBookings.length > 0 ? (
              upcomingBookings.map((booking) => (
                <BookingCard 
                  key={booking.id} 
                  booking={booking}
                  cruise={getCruiseForBooking(booking)}
                />
              ))
            ) : (
              <div className="text-center p-8 bg-gray-50 rounded-lg">
                <Ship className="h-12 w-12 mx-auto mb-4 text-gray-400" />
                <h3 className="text-xl font-semibold text-gray-700 mb-2">No Upcoming Cruises</h3>
                <p className="text-gray-600 mb-6">You don't have any upcoming cruise bookings.</p>
                <Button 
                  className="bg-[#1a75bc] hover:bg-[#0d4677]"
                  onClick={() => navigate('/destinations')}
                >
                  Browse Cruises
                </Button>
              </div>
            )}
          </TabsContent>
          
          <TabsContent value="past">
            {pastBookings.length > 0 ? (
              pastBookings.map((booking) => (
                <BookingCard 
                  key={booking.id} 
                  booking={booking}
                  cruise={getCruiseForBooking(booking)}
                />
              ))
            ) : (
              <div className="text-center p-8 bg-gray-50 rounded-lg">
                <Clock className="h-12 w-12 mx-auto mb-4 text-gray-400" />
                <h3 className="text-xl font-semibold text-gray-700 mb-2">No Past Cruises</h3>
                <p className="text-gray-600">You don't have any past cruise bookings.</p>
              </div>
            )}
          </TabsContent>
          
          <TabsContent value="cancelled">
            {cancelledBookings.length > 0 ? (
              cancelledBookings.map((booking) => (
                <BookingCard 
                  key={booking.id} 
                  booking={booking}
                  cruise={getCruiseForBooking(booking)}
                />
              ))
            ) : (
              <div className="text-center p-8 bg-gray-50 rounded-lg">
                <Check className="h-12 w-12 mx-auto mb-4 text-gray-400" />
                <h3 className="text-xl font-semibold text-gray-700 mb-2">No Cancelled Bookings</h3>
                <p className="text-gray-600">You don't have any cancelled cruise bookings.</p>
              </div>
            )}
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
};

export default Profile;
