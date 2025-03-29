import { useState, useEffect } from "react";
import { Link, useLocation } from "wouter";
import { motion, AnimatePresence } from "framer-motion";
import { useMediaQuery } from "@/hooks/use-mobile";
import { useAuth } from "@/hooks/use-auth";
import { Menu, X, ChevronDown } from "lucide-react";

const Navbar = () => {
  const [isOpen, setIsOpen] = useState(false);
  const [destinationsDropdown, setDestinationsDropdown] = useState(false);
  const [cruisesDropdown, setCruisesDropdown] = useState(false);
  const isMobile = useMediaQuery("(max-width: 768px)");
  const [location, navigate] = useLocation();
  const { user, logoutMutation } = useAuth();
  
  const handleLogout = () => {
    logoutMutation.mutate();
  };
  
  // Close mobile menu when location changes
  useEffect(() => {
    setIsOpen(false);
  }, [location]);

  // Handle desktop dropdown hover
  const handleDestinationsHover = () => {
    if (!isMobile) setDestinationsDropdown(true);
  };
  
  const handleCruisesHover = () => {
    if (!isMobile) setCruisesDropdown(true);
  };
  
  const handleMouseLeave = () => {
    if (!isMobile) {
      setDestinationsDropdown(false);
      setCruisesDropdown(false);
    }
  };
  
  // Handle mobile dropdown click
  const toggleDestinationsDropdown = () => {
    if (isMobile) {
      setDestinationsDropdown(!destinationsDropdown);
      if (cruisesDropdown) setCruisesDropdown(false);
    }
  };
  
  const toggleCruisesDropdown = () => {
    if (isMobile) {
      setCruisesDropdown(!cruisesDropdown);
      if (destinationsDropdown) setDestinationsDropdown(false);
    }
  };

  return (
    <nav className="bg-white shadow-md fixed top-0 left-0 right-0 z-50">
      <div className="container mx-auto px-4 py-3">
        <div className="flex justify-between items-center">
          <div className="flex items-center">
            <Link href="/" className="flex items-center">
              <div className="text-primary-dark font-montserrat font-bold text-2xl">
                <span className="text-[#1a75bc]">Ocean</span>
                <span className="text-[#ff7043]">View</span>
              </div>
            </Link>
            
            <div className="hidden md:flex ml-10 space-x-8">
              <div 
                className="relative"
                onMouseEnter={handleDestinationsHover}
                onMouseLeave={handleMouseLeave}
              >
                <div 
                  className="font-medium text-gray-700 hover:text-[#0d4677] px-2 py-1 flex items-center cursor-pointer"
                  onClick={toggleDestinationsDropdown}
                >
                  Destinations <ChevronDown className="ml-1 h-4 w-4" />
                </div>
                
                {destinationsDropdown && (
                  <div className="absolute top-full mt-1 p-4 bg-white min-w-[200px] rounded-md shadow-lg z-50">
                    <div className="grid grid-cols-2 gap-4">
                      <Link href="/destinations?region=Caribbean" className="hover:text-[#0d4677]">Caribbean</Link>
                      <Link href="/destinations?region=Mediterranean" className="hover:text-[#0d4677]">Mediterranean</Link>
                      <Link href="/destinations?region=Alaska" className="hover:text-[#0d4677]">Alaska</Link>
                      <Link href="/destinations?region=Asia" className="hover:text-[#0d4677]">Asia</Link>
                      <Link href="/destinations?region=Europe" className="hover:text-[#0d4677]">Europe</Link>
                      <Link href="/destinations?region=Australia" className="hover:text-[#0d4677]">Australia</Link>
                    </div>
                  </div>
                )}
              </div>
              
              <div 
                className="relative"
                onMouseEnter={handleCruisesHover}
                onMouseLeave={handleMouseLeave}
              >
                <div 
                  className="font-medium text-gray-700 hover:text-[#0d4677] px-2 py-1 flex items-center cursor-pointer"
                  onClick={toggleCruisesDropdown}
                >
                  Cruises <ChevronDown className="ml-1 h-4 w-4" />
                </div>
                
                {cruisesDropdown && (
                  <div className="absolute top-full mt-1 p-4 bg-white min-w-[200px] rounded-md shadow-lg z-50">
                    <div className="flex flex-col space-y-2">
                      <Link href="/destinations" className="hover:text-[#0d4677]">All Cruises</Link>
                      <Link href="/destinations?deals=last-minute" className="hover:text-[#0d4677]">Last Minute Deals</Link>
                      <Link href="/destinations?type=family" className="hover:text-[#0d4677]">Family Cruises</Link>
                      <Link href="/destinations?type=luxury" className="hover:text-[#0d4677]">Luxury Cruises</Link>
                    </div>
                  </div>
                )}
              </div>
              
              <Link href="/destinations?deals=true" className="font-medium text-gray-700 hover:text-[#0d4677] px-2 py-1">
                Deals
              </Link>
              <Link href="/#onboard" className="font-medium text-gray-700 hover:text-[#0d4677] px-2 py-1">
                Onboard Experience
              </Link>
            </div>
          </div>
          
          <div className="flex items-center space-x-4">
            {user ? (
              <div className="hidden md:flex items-center space-x-4">
                <Link href="/profile" className="text-gray-700 hover:text-[#0d4677]">
                  <span className="font-medium">{user.firstName || user.username}</span>
                </Link>
                <button 
                  onClick={handleLogout}
                  className="text-gray-700 hover:text-[#0d4677]"
                  disabled={logoutMutation.isPending}
                >
                  Logout
                </button>
              </div>
            ) : (
              <Link href="/auth" className="hidden md:block text-gray-700 hover:text-[#0d4677]">
                <span className="flex items-center">
                  <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                  </svg>
                  Login
                </span>
              </Link>
            )}
            <Link href="/destinations" className="bg-[#ff7043] hover:bg-[#e65100] text-white font-montserrat px-6 py-2 rounded-full transition duration-300 text-sm">
              Book Now
            </Link>
            
            <button 
              className="md:hidden text-gray-700"
              onClick={() => setIsOpen(!isOpen)}
            >
              {isOpen ? (
                <X className="h-6 w-6" />
              ) : (
                <Menu className="h-6 w-6" />
              )}
            </button>
          </div>
        </div>
      </div>
      
      {/* Mobile menu */}
      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.3 }}
            className="md:hidden overflow-hidden bg-[#f5f7fa]"
          >
            <div className="px-4 py-2 space-y-3">
              <div>
                <div 
                  className="flex justify-between items-center py-2 text-gray-700"
                  onClick={toggleDestinationsDropdown}
                >
                  <span>Destinations</span>
                  <ChevronDown className={`h-4 w-4 transform transition-transform ${destinationsDropdown ? 'rotate-180' : ''}`} />
                </div>
                
                {destinationsDropdown && (
                  <div className="pl-4 space-y-2 py-2">
                    <Link href="/destinations?region=Caribbean" className="block text-gray-600">Caribbean</Link>
                    <Link href="/destinations?region=Mediterranean" className="block text-gray-600">Mediterranean</Link>
                    <Link href="/destinations?region=Alaska" className="block text-gray-600">Alaska</Link>
                    <Link href="/destinations?region=Asia" className="block text-gray-600">Asia</Link>
                    <Link href="/destinations?region=Europe" className="block text-gray-600">Europe</Link>
                    <Link href="/destinations?region=Australia" className="block text-gray-600">Australia</Link>
                  </div>
                )}
              </div>
              
              <div>
                <div 
                  className="flex justify-between items-center py-2 text-gray-700"
                  onClick={toggleCruisesDropdown}
                >
                  <span>Cruises</span>
                  <ChevronDown className={`h-4 w-4 transform transition-transform ${cruisesDropdown ? 'rotate-180' : ''}`} />
                </div>
                
                {cruisesDropdown && (
                  <div className="pl-4 space-y-2 py-2">
                    <Link href="/destinations" className="block text-gray-600">All Cruises</Link>
                    <Link href="/destinations?deals=last-minute" className="block text-gray-600">Last Minute Deals</Link>
                    <Link href="/destinations?type=family" className="block text-gray-600">Family Cruises</Link>
                    <Link href="/destinations?type=luxury" className="block text-gray-600">Luxury Cruises</Link>
                  </div>
                )}
              </div>
              
              <Link href="/destinations?deals=true" className="block py-2 text-gray-700">Deals</Link>
              <Link href="/#onboard" className="block py-2 text-gray-700">Onboard Experience</Link>
              
              {user ? (
                <>
                  <Link href="/profile" className="block py-2 text-gray-700">Profile</Link>
                  <button 
                    onClick={handleLogout}
                    className="block py-2 text-gray-700 w-full text-left"
                    disabled={logoutMutation.isPending}
                  >
                    Logout
                  </button>
                </>
              ) : (
                <Link href="/auth" className="block py-2 text-gray-700">Login</Link>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </nav>
  );
};

export default Navbar;
