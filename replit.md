# Vendor Column Restorer — Backend System

## Overview

A Shopify Admin UI Extension backend system that restores the Vendor column in product lists and enables vendor-based operations. The system provides comprehensive vendor management, bulk product operations, CSV export functionality, and real-time monitoring through a React-based admin dashboard.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
- **Framework**: React with TypeScript using Vite for build tooling
- **UI Library**: Shadcn/ui components built on Radix UI primitives for accessible, modern interfaces
- **Styling**: Tailwind CSS with custom design tokens and CSS variables for theming
- **State Management**: TanStack Query (React Query) for server state management and caching
- **Routing**: Wouter for lightweight client-side routing
- **Forms**: React Hook Form with Zod validation for type-safe form handling

### Backend Architecture
- **Runtime**: Node.js with TypeScript using ESM modules
- **Framework**: Express.js for HTTP server and API routing
- **Database**: PostgreSQL with Drizzle ORM for type-safe database operations
- **Database Connection**: Neon serverless PostgreSQL with connection pooling
- **Migration System**: Drizzle Kit for schema migrations and database management
- **Middleware**: Custom rate limiting, logging, and error handling middleware

### Data Storage Architecture
- **ORM**: Drizzle ORM with schema-first approach for type safety
- **Schema Design**: Modular schema with separate tables for users, shop settings, bulk jobs, vendors, API logs, and system metrics
- **Connection Management**: Connection pooling with @neondatabase/serverless
- **Data Validation**: Zod schemas generated from Drizzle schema for runtime validation

### API Design
- **Pattern**: RESTful API design with structured JSON responses
- **Rate Limiting**: Multi-tier rate limiting (general, bulk operations, exports, Shopify API)
- **Logging**: Comprehensive API call logging with performance metrics
- **Error Handling**: Centralized error handling with proper HTTP status codes
- **Bulk Operations**: Asynchronous job processing with status tracking

### Authentication & Security
- **Shop Authentication**: OAuth integration with Shopify stores
- **Token Management**: Encrypted storage of Shopify access tokens using AES-256-GCM
- **Rate Limiting**: Protection against abuse with configurable limits
- **Input Validation**: Zod validation on all API endpoints

### Service Layer Architecture
- **Shopify Integration**: Dedicated service for GraphQL API interactions
- **Bulk Job Processing**: Asynchronous job processor with retry logic
- **CSV Export**: Streaming CSV generation with signed download URLs
- **Authentication Service**: Token encryption/decryption and credential management

## External Dependencies

### Core Dependencies
- **@neondatabase/serverless**: Serverless PostgreSQL database connection
- **drizzle-orm & drizzle-kit**: Type-safe ORM and migration tooling
- **express**: Web framework for API server
- **@tanstack/react-query**: Server state management for React
- **zod**: Runtime type validation and schema definition

### UI Components
- **@radix-ui/***: Comprehensive accessible UI primitives (dialogs, forms, navigation, etc.)
- **class-variance-authority**: Type-safe CSS class variants
- **tailwindcss**: Utility-first CSS framework
- **lucide-react**: Icon library for consistent iconography

### Development Tools
- **vite**: Fast build tool with HMR for development
- **typescript**: Type safety across frontend and backend
- **@replit/vite-plugin-***: Replit-specific development enhancements
- **esbuild**: Fast JavaScript bundler for production builds

### Shopify Integration
- **Shopify Admin GraphQL API**: Product data retrieval and bulk operations
- **OAuth 2.0**: Shop authentication and authorization
- **Webhooks**: Real-time updates from Shopify (planned integration)

### Monitoring & Logging
- **Custom Logger**: Structured JSON logging with configurable levels
- **API Metrics**: Response time tracking and error rate monitoring
- **System Metrics**: Performance and usage analytics storage