#!/usr/bin/env python3
"""
Database Creation Script for Cruise Booking Platform

This script creates the complete PostgreSQL database schema for the Cruise Booking Platform
based on the schema defined in the project. It checks if the specified database exists,
creates it if it doesn't, and then sets up all tables, enums, and relationships.

Usage:
    python create_db.py [--db_name DBNAME]

Options:
    --db_name     Optional database name (default: cruise_booking)
"""

import sys
import os
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
import argparse
from psycopg2 import sql

DEFAULT_DB_NAME = "cruise_booking"


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Create the Cruise Booking Platform database schema.")
    parser.add_argument("--db_name", type=str, default=DEFAULT_DB_NAME,
                        help=f"Database name (default: {DEFAULT_DB_NAME})")
    return parser.parse_args()


def get_connection_params():
    """Get database connection parameters from environment variables or use defaults."""
    host = os.environ.get("PGHOST", "localhost")
    port = os.environ.get("PGPORT", "5432")
    user = os.environ.get("PGUSER", "postgres")
    password = os.environ.get("PGPASSWORD", "postgres")
    
    return {
        "host": host,
        "port": port,
        "user": user,
        "password": password
    }


def check_database_exists(db_name, conn_params):
    """Check if the specified database exists."""
    conn = psycopg2.connect(
        host=conn_params["host"],
        port=conn_params["port"],
        user=conn_params["user"],
        password=conn_params["password"],
        dbname="postgres"  # Connect to default database to check if our DB exists
    )
    conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM pg_database WHERE datname = %s", (db_name,))
    exists = cursor.fetchone() is not None
    
    cursor.close()
    conn.close()
    
    return exists


def create_database(db_name, conn_params):
    """Create a new database if it doesn't exist."""
    conn = psycopg2.connect(
        host=conn_params["host"],
        port=conn_params["port"],
        user=conn_params["user"],
        password=conn_params["password"],
        dbname="postgres"  # Connect to default database
    )
    conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    
    cursor = conn.cursor()
    
    print(f"Creating database '{db_name}'...")
    cursor.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(db_name)))
    
    cursor.close()
    conn.close()
    
    print(f"Database '{db_name}' created successfully.")


def create_schema(db_name, conn_params):
    """Create the complete database schema."""
    conn = psycopg2.connect(
        host=conn_params["host"],
        port=conn_params["port"],
        user=conn_params["user"],
        password=conn_params["password"],
        dbname=db_name
    )
    conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    
    cursor = conn.cursor()
    
    # Create enums first
    print("Creating enum types...")
    cursor.execute("""
    CREATE TYPE booking_status AS ENUM (
        'pending',
        'confirmed',
        'in_progress',
        'completed',
        'cancelled',
        'refunded'
    );

    CREATE TYPE enquiry_status AS ENUM (
        'submitted',
        'in_review',
        'responded',
        'closed'
    );

    CREATE TYPE cabin_type AS ENUM (
        'Interior', 
        'Ocean View Stateroom', 
        'Balcony Stateroom', 
        'Suite'
    );

    CREATE TYPE cancellation_reason AS ENUM (
        'customer_request',
        'schedule_change',
        'medical',
        'weather',
        'emergency',
        'policy_violation',
        'other'
    );

    CREATE TYPE payment_status AS ENUM (
        'pending',
        'processing',
        'completed',
        'failed',
        'refunded',
        'partially_refunded'
    );

    CREATE TYPE payment_method AS ENUM (
        'credit_card',
        'debit_card',
        'paypal',
        'bank_transfer',
        'stripe',
        'apple_pay',
        'google_pay'
    );
    """)
    
    print("Enum types created successfully.")
    
    # Create tables
    print("Creating database tables...")
    
    # Users table
    cursor.execute("""
    CREATE TABLE users (
        id SERIAL PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        first_name TEXT,
        last_name TEXT,
        phone TEXT,
        address TEXT,
        city TEXT,
        state TEXT,
        zip_code TEXT,
        country TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
        last_login TIMESTAMP,
        is_verified BOOLEAN DEFAULT FALSE,
        reset_token TEXT,
        reset_token_expiry TIMESTAMP
    );
    """)
    
    # Destinations table
    cursor.execute("""
    CREATE TABLE destinations (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT NOT NULL,
        image_url TEXT NOT NULL,
        price_from INTEGER NOT NULL,
        rating DOUBLE PRECISION NOT NULL,
        cruise_count INTEGER NOT NULL,
        duration_range TEXT NOT NULL
    );
    """)
    
    # Cruises table
    cursor.execute("""
    CREATE TABLE cruises (
        id SERIAL PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        destination_id INTEGER NOT NULL,
        image_url TEXT NOT NULL,
        departure_from TEXT NOT NULL,
        duration INTEGER NOT NULL,
        price_per_person INTEGER NOT NULL,
        original_price INTEGER,
        cabin_type TEXT NOT NULL,
        inclusions TEXT NOT NULL,
        is_best_seller BOOLEAN DEFAULT FALSE,
        is_new_itinerary BOOLEAN DEFAULT FALSE,
        rating DOUBLE PRECISION NOT NULL,
        available_packages TEXT[] NOT NULL,
        available_dates DATE[],
        CONSTRAINT fk_destination
            FOREIGN KEY (destination_id)
            REFERENCES destinations(id)
            ON DELETE CASCADE
    );
    """)
    
    # Cabin Types table
    cursor.execute("""
    CREATE TABLE cabin_types (
        id SERIAL PRIMARY KEY,
        cruise_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        description TEXT NOT NULL,
        price_modifier INTEGER NOT NULL DEFAULT 0,
        capacity INTEGER NOT NULL,
        amenities TEXT[],
        image_url TEXT,
        CONSTRAINT fk_cruise
            FOREIGN KEY (cruise_id)
            REFERENCES cruises(id)
            ON DELETE CASCADE
    );
    """)
    
    # Bookings table
    cursor.execute("""
    CREATE TABLE bookings (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        cruise_id INTEGER NOT NULL,
        cabin_type_id INTEGER,
        booking_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
        departure_date DATE NOT NULL,
        return_date DATE NOT NULL,
        total_price INTEGER NOT NULL,
        number_of_guests INTEGER NOT NULL,
        cabin_type TEXT NOT NULL,
        guest_details JSONB NOT NULL,
        status booking_status NOT NULL DEFAULT 'pending',
        status_history JSONB,
        payment_status payment_status DEFAULT 'pending',
        special_requests TEXT,
        booking_reference TEXT NOT NULL UNIQUE,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
        cancellation_date TIMESTAMP,
        cancellation_reason cancellation_reason,
        cancellation_notes TEXT,
        refund_amount INTEGER,
        refund_date TIMESTAMP,
        checked_in BOOLEAN DEFAULT FALSE,
        check_in_date TIMESTAMP,
        terms_accepted BOOLEAN DEFAULT FALSE NOT NULL,
        last_notification_sent TIMESTAMP,
        CONSTRAINT fk_user
            FOREIGN KEY (user_id)
            REFERENCES users(id)
            ON DELETE CASCADE,
        CONSTRAINT fk_cruise
            FOREIGN KEY (cruise_id)
            REFERENCES cruises(id)
            ON DELETE CASCADE,
        CONSTRAINT fk_cabin_type
            FOREIGN KEY (cabin_type_id)
            REFERENCES cabin_types(id)
            ON DELETE SET NULL
    );
    """)
    
    # Amenities table
    cursor.execute("""
    CREATE TABLE amenities (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT NOT NULL,
        image_url TEXT NOT NULL,
        category TEXT
    );
    """)
    
    # Testimonials table
    cursor.execute("""
    CREATE TABLE testimonials (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        cruise_name TEXT NOT NULL,
        comment TEXT NOT NULL,
        rating INTEGER NOT NULL,
        avatar_url TEXT,
        cruise_id INTEGER,
        user_id INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
        is_verified BOOLEAN DEFAULT FALSE,
        CONSTRAINT fk_cruise
            FOREIGN KEY (cruise_id)
            REFERENCES cruises(id)
            ON DELETE SET NULL,
        CONSTRAINT fk_user
            FOREIGN KEY (user_id)
            REFERENCES users(id)
            ON DELETE SET NULL
    );
    """)
    
    # Enquiries table
    cursor.execute("""
    CREATE TABLE enquiries (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        phone TEXT,
        subject TEXT NOT NULL,
        message TEXT NOT NULL,
        status enquiry_status DEFAULT 'submitted' NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
        assigned_to_user_id INTEGER,
        user_id INTEGER,
        CONSTRAINT fk_assigned_user
            FOREIGN KEY (assigned_to_user_id)
            REFERENCES users(id)
            ON DELETE SET NULL,
        CONSTRAINT fk_user
            FOREIGN KEY (user_id)
            REFERENCES users(id)
            ON DELETE SET NULL
    );
    """)
    
    # Enquiry Responses table
    cursor.execute("""
    CREATE TABLE enquiry_responses (
        id SERIAL PRIMARY KEY,
        enquiry_id INTEGER NOT NULL,
        response_text TEXT NOT NULL,
        responded_by_user_id INTEGER,
        responded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
        CONSTRAINT fk_enquiry
            FOREIGN KEY (enquiry_id)
            REFERENCES enquiries(id)
            ON DELETE CASCADE,
        CONSTRAINT fk_user
            FOREIGN KEY (responded_by_user_id)
            REFERENCES users(id)
            ON DELETE SET NULL
    );
    """)
    
    # Payments table
    cursor.execute("""
    CREATE TABLE payments (
        id SERIAL PRIMARY KEY,
        booking_id INTEGER NOT NULL,
        amount INTEGER NOT NULL,
        currency TEXT DEFAULT 'USD' NOT NULL,
        status payment_status NOT NULL DEFAULT 'pending',
        payment_method payment_method NOT NULL,
        transaction_id TEXT,
        payment_intent_id TEXT,
        payment_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
        billing_address JSONB,
        card_last4 TEXT,
        expiry_month TEXT,
        expiry_year TEXT,
        cardholder_name TEXT,
        refund_amount INTEGER,
        refund_date TIMESTAMP,
        gateway_response JSONB,
        CONSTRAINT fk_booking
            FOREIGN KEY (booking_id)
            REFERENCES bookings(id)
            ON DELETE CASCADE
    );
    """)
    
    # Session table for Passport.js (connect-pg-simple)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS "session" (
        "sid" varchar NOT NULL COLLATE "default",
        "sess" json NOT NULL,
        "expire" timestamp(6) NOT NULL,
        CONSTRAINT "session_pkey" PRIMARY KEY ("sid")
    );
    
    CREATE INDEX IF NOT EXISTS "IDX_session_expire" ON "session" ("expire");
    """)
    
    # Create indexes for performance
    print("Creating database indexes...")
    cursor.execute("""
    -- Indexes for users table
    CREATE INDEX idx_users_username ON users(username);
    CREATE INDEX idx_users_email ON users(email);
    
    -- Indexes for cruises table
    CREATE INDEX idx_cruises_destination_id ON cruises(destination_id);
    CREATE INDEX idx_cruises_is_best_seller ON cruises(is_best_seller);
    
    -- Indexes for bookings table
    CREATE INDEX idx_bookings_user_id ON bookings(user_id);
    CREATE INDEX idx_bookings_cruise_id ON bookings(cruise_id);
    CREATE INDEX idx_bookings_status ON bookings(status);
    CREATE INDEX idx_bookings_booking_reference ON bookings(booking_reference);
    CREATE INDEX idx_bookings_departure_date ON bookings(departure_date);
    
    -- Indexes for payments table
    CREATE INDEX idx_payments_booking_id ON payments(booking_id);
    CREATE INDEX idx_payments_status ON payments(status);
    
    -- Indexes for enquiries table
    CREATE INDEX idx_enquiries_user_id ON enquiries(user_id);
    CREATE INDEX idx_enquiries_status ON enquiries(status);
    
    -- Indexes for testimonials table
    CREATE INDEX idx_testimonials_cruise_id ON testimonials(cruise_id);
    CREATE INDEX idx_testimonials_is_verified ON testimonials(is_verified);
    
    -- Indexes for cabin_types table
    CREATE INDEX idx_cabin_types_cruise_id ON cabin_types(cruise_id);
    """)
    
    # Add triggers for updated_at timestamps
    print("Creating timestamp triggers...")
    cursor.execute("""
    -- Function to update timestamps
    CREATE OR REPLACE FUNCTION update_modified_column()
    RETURNS TRIGGER AS $$
    BEGIN
        NEW.updated_at = CURRENT_TIMESTAMP;
        RETURN NEW;
    END;
    $$ LANGUAGE plpgsql;
    
    -- Trigger for users table
    CREATE TRIGGER update_users_timestamp
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_modified_column();
    
    -- Trigger for bookings table
    CREATE TRIGGER update_bookings_timestamp
    BEFORE UPDATE ON bookings
    FOR EACH ROW
    EXECUTE FUNCTION update_modified_column();
    
    -- Trigger for enquiries table
    CREATE TRIGGER update_enquiries_timestamp
    BEFORE UPDATE ON enquiries
    FOR EACH ROW
    EXECUTE FUNCTION update_modified_column();
    """)
    
    cursor.close()
    conn.close()
    
    print("Database schema created successfully.")


def main():
    """Main function to orchestrate database creation."""
    args = parse_arguments()
    db_name = args.db_name
    
    print(f"Starting database setup for '{db_name}'...")
    
    conn_params = get_connection_params()
    
    # Check if database exists
    if check_database_exists(db_name, conn_params):
        print(f"Database '{db_name}' already exists.")
        proceed = input("Do you want to drop the existing database and recreate it? (y/n): ").lower()
        if proceed == 'y':
            conn = psycopg2.connect(
                host=conn_params["host"],
                port=conn_params["port"],
                user=conn_params["user"],
                password=conn_params["password"],
                dbname="postgres"  # Connect to default database
            )
            conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
            cursor = conn.cursor()
            
            # Force disconnect all existing connections
            cursor.execute(f"""
            SELECT pg_terminate_backend(pg_stat_activity.pid)
            FROM pg_stat_activity
            WHERE pg_stat_activity.datname = '{db_name}'
            AND pid <> pg_backend_pid();
            """)
            
            # Drop the database
            cursor.execute(f"DROP DATABASE IF EXISTS {db_name}")
            cursor.close()
            conn.close()
            
            # Create the database again
            create_database(db_name, conn_params)
            create_schema(db_name, conn_params)
        else:
            print("Exiting without modifying the existing database.")
            return
    else:
        # Database doesn't exist, create it
        create_database(db_name, conn_params)
        create_schema(db_name, conn_params)
    
    print(f"""
Database setup complete!

Connection details:
- Host: {conn_params['host']}
- Port: {conn_params['port']}
- Database: {db_name}
- User: {conn_params['user']}

To connect using psql:
psql -h {conn_params['host']} -p {conn_params['port']} -U {conn_params['user']} -d {db_name}

To use with the application, set the DATABASE_URL environment variable:
DATABASE_URL=postgresql://{conn_params['user']}:{conn_params['password']}@{conn_params['host']}:{conn_params['port']}/{db_name}
""")


if __name__ == "__main__":
    main()