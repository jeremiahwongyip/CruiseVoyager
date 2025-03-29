import { useEffect } from "react";
import { Switch, Route, useLocation } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { AuthProvider } from "@/hooks/use-auth";
import { ProtectedRoute } from "@/lib/protected-route";
import NotFound from "@/pages/not-found";
import Home from "@/pages/home";
import AuthPage from "@/pages/auth-page";
import Profile from "@/pages/profile";
import Destinations from "@/pages/destinations";
import CruiseDetails from "@/pages/cruise-details";
import Booking from "@/pages/booking";
import Contact from "@/pages/contact";
import Navbar from "@/components/layout/navbar";
import Footer from "@/components/layout/footer";

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

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <Router />
        <Toaster />
      </AuthProvider>
    </QueryClientProvider>
  );
}

export default App;
