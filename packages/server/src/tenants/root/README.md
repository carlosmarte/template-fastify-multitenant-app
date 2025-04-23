tenant1: is the example tenant name

<project_structure>
src/tenants/tenant1/
├── config.js # Main tenant configuration
├── index.mjs # Optional custom tenant ID definition
├── routes/ # API endpoints and route handlers
│ ├── index.mjs # Main tenant routes
│ ├── users.mjs # User management routes
│ └── ... # Feature-specific routes
├── schemas/ # JSON schema definitions
│ ├── user.mjs # User-related schemas
│ └── ... # Feature-specific schemas
├── services/ # Business logic implementation
│ ├── userService.mjs # User management service
│ └── ... # Feature-specific services
├── plugins/ # Tenant-specific plugins
│ ├── analytics/ # Example analytics plugin
│ │ └── index.mjs # Plugin entry point
│ └── ... # Other tenant plugins
├── middleware/ # Custom middleware
│ └── tenantSpecificAuth.mjs # Tenant-specific authentication
├── models/ # Data models (optional)
│ └── user.mjs # User model definition
├── database/ # Database-related files
│ ├── migrations/ # Schema migrations
│ │ └── 001_initial_schema.sql # Initial database schema
│ └── seeds/ # Seed data
│ └── sample_data.sql # Sample data for development
├── lib/ # Helper utilities
│ └── validators.mjs # Custom validation helpers
├── hooks/ # Custom Fastify hooks
│ └── auditLogger.mjs # Example audit logging hook
└── test/ # Tests for this tenant
├── routes/ # Route tests
│ └── users.test.mjs # User routes tests
└── services/ # Service tests
└── userService.test.mjs # User service tests
</project_structure>

# src/tenants/tenant1/Config.js

```js
export default {
  // Core tenant identity
  id: "tenant1", // Internal tenant ID (can be overridden in index.mjs)
  name: "Acme Corporation", // Display name
  description: "Enterprise customer portal", // Description
  active: true, // Whether tenant is active
  version: "1.0.0", // Tenant version

  // Access and security
  domains: ["tenant1.example.com"], // Custom domains for this tenant
  cors: {
    // CORS settings
    origins: ["https://tenant1.example.com"],
    credentials: true,
  },

  // Appearance
  branding: {},

  // Feature flags
  features: {},

  // External integrations
  integrations: {},

  // API configuration
  api: {
    rateLimits: {
      // Rate limiting settings
      enabled: true,
      requestsPerMinute: 100,
      burstLimit: 200,
    },
    defaultVersion: "v1", // Default API version
    versioning: {
      // API versioning
      enabled: true,
      supportedVersions: ["v1", "v2"],
    },
  },

  // Database configuration
  database: {
    name: "tenant1_db", // Database name (if tenant has own DB)
    schema: "tenant1", // Schema name (for shared DB)
    maxConnections: 10, // Max DB connections
    connectionTimeout: 30000, // Connection timeout (ms)
  },

  // Email configuration
  email: {},

  // Localization
  localization: {
    defaultLocale: "en-US", // Default locale
    supportedLocales: ["en-US", "es-ES", "fr-FR"], // Supported locales
    timezone: "America/New_York", // Default timezone
  },

  // Analytics
  analytics: {
    enabled: true, // Enable analytics
    provider: "google-analytics", // Analytics provider
    trackingId: "UA-XXXXXXXX-1", // Tracking ID
    autoTrackPageViews: true, // Auto-track page views
  },

  // Compliance
  compliance: {
    gdpr: {
      // GDPR settings
      enabled: true,
      dataDeletionPeriod: 30, // Days to keep data after deletion request
    },
    dataRetention: {
      // Data retention policies
      logs: 90, // Days to keep logs
      userActivity: 365, // Days to keep user activity
    },
  },
};
```

# src/tenants/tenant1/index.mjs

```js
// Override the directory name as the tenant ID
export const NAME = "acme-corporation";

// Export initialization function
export default async function initialize(app, options) {
  app.log.info(`Initializing tenant: ${NAME}`);

  // Perform tenant-specific initialization
  const tenantContext = {
    initialized: new Date().toISOString(),
    customData: {},
  };

  // Set up any tenant-specific hooks
  app.addHook("onRequest", async (request, reply) => {
    // Add tenant-specific context to request
    request.tenantContext = {
      ...request.tenantContext,
      ...tenantContext,
    };
  });

  // Return tenant context to be stored with tenant
  return tenantContext;
}
```

# src/tenants/tenant1/routes/index.mjs

```js
export default async function routes(fastify, options) {
  const { tenant, config } = options;

  // Root route - tenant info
  fastify.get(
    "/",
    {
      schema: {
        response: {
          200: {
            type: "object",
            properties: {
              tenant: { type: "string" },
              message: { type: "string" },
              version: { type: "string" },
            },
          },
        },
      },
    },
    async (request, reply) => {
      return {
        tenant: config.name,
        message: `Welcome to ${config.name}!`,
        version: config.version,
      };
    }
  );

  // Health check
  fastify.get("/health", async (request, reply) => {
    // Perform tenant-specific health checks
    const dbStatus = await checkDatabaseConnection(request.tenant);

    return {
      status: dbStatus ? "ok" : "degraded",
      timestamp: new Date().toISOString(),
      services: {
        database: dbStatus ? "ok" : "error",
        cache: "ok",
      },
    };
  });

  // Not found handler for this tenant
  fastify.setNotFoundHandler((request, reply) => {
    reply.code(404).send({
      error: "Not Found",
      message: `The requested resource doesn't exist on ${config.name}`,
      tenant: config.id,
    });
  });
}

// Helper function for health check
async function checkDatabaseConnection(tenant) {
  try {
    // Perform a simple query to check DB connection
    // In a real implementation, use tenant.db or fastify.db
    return true;
  } catch (err) {
    return false;
  }
}
```

# src/tenants/tenant1/routes/users.mjs

```js
export default async function userRoutes(fastify, options) {
  const { tenant, config } = options;
  const { userService } = fastify.services;

  // Authentication middleware
  const authenticate = async (request, reply) => {
    if (!request.user) {
      reply.code(401).send({
        error: "Unauthorized",
        message: "Authentication required",
      });
    }
  };

  // Authorization middleware for admin-only routes
  const requireAdmin = async (request, reply) => {
    await authenticate(request, reply);

    if (request.user.role !== "admin") {
      reply.code(403).send({
        error: "Forbidden",
        message: "Admin privileges required",
      });
    }
  };

  // GET /users - List users
  fastify.get(
    "/users",
    {
      onRequest: authenticate,
        response: {
          200: fastify.getSchema("userListResponse"),
        },
      },
    },
    async (request, reply) => {
      const { limit, offset, sort } = request.query;
      const users = await userService.getUsers(request.tenantId, {
        limit,
        offset,
        sort,
      });

      return { users };
    }
  );

}
```

# src/tenants/tenant1/schemas/user.mjs

```js
export default {
  // Schema for list of users response
  userListResponse: {
    $id: "userListResponse",
    type: "object",
    properties: {
      users: {
        type: "array",
        items: { $ref: "userBase" },
      },
      pagination: {
        type: "object",
        properties: {
          total: { type: "integer" },
          offset: { type: "integer" },
          limit: { type: "integer" },
          hasMore: { type: "boolean" },
        },
      },
    },
  },
};
```

# src/tenants/tenant1/services/userService.mjs

```js
export default class UserService {
  constructor(db, options = {}) {
    this.db = db;
    this.options = options;
    this.config = options.config || {};
    this.jwtSecret = process.env.JWT_SECRET || "your-secret-key"; // Should be in environment variables
    this.tokenExpiration = "1h";
  }

  // User authentication
  async authenticate(tenantId, email, password) {}

  // Get all users for a tenant with pagination
  async getUsers(tenantId, options = {}) {}

  // Get a specific user by ID
  async getUserById(tenantId, userId) {}

  // Get a user by email
  async getUserByEmail(tenantId, email) {}

  // Create a new user
  async createUser(tenantId, userData) {}

  // Update an existing user
  async updateUser(tenantId, userId, userData) {}

  // Delete a user
  async deleteUser(tenantId, userId) {}

  // Change user password
  async changePassword(tenantId, userId, currentPassword, newPassword) {}

  // Request password reset
  async requestPasswordReset(tenantId, email) {}

  // Reset password with token
  async resetPassword(tenantId, token, newPassword) {}

  _sanitizeUser(user) {
    if (!user) return null;

    // Convert snake_case database fields to camelCase for API
    const sanitized = {
      id: user.id,
      firstName: user.first_name,
      lastName: user.last_name,
      email: user.email,
      role: user.role,
      status: user.status,
      createdAt: user.created_at,
      updatedAt: user.updated_at,
      lastLoginAt: user.last_login_at,
      metadata:
        typeof user.metadata === "string"
          ? JSON.parse(user.metadata)
          : user.metadata || {},
    };

    return sanitized;
  }

  // Hash password using bcrypt
  async _hashPassword(password) {
    const saltRounds = 10;
    return await bcrypt.hash(password, saltRounds);
  }
}
```

# src/tenants/tenant1/plugins/analytics/index.mjs

```js
// Tenant-specific analytics plugin
export default async function analyticsPlugin(fastify, options) {
  const { tenant, config } = options;

  // Get analytics configuration from tenant config
  const analyticsConfig = config.analytics || {};

  if (!analyticsConfig.enabled) {
    fastify.log.info(`Analytics disabled for tenant ${tenant}`);
    return;
  }

  // Initialize analytics provider based on configuration
  const provider = initializeProvider(analyticsConfig, fastify.log);

  // Decorate fastify instance with tenant-specific analytics service
  fastify.decorate("analytics", {
    // Track custom event
    trackEvent: async (eventName, data = {}) => {
      try {
        // Add tenant information
        const eventData = {
          ...data,
          tenant,
          timestamp: new Date().toISOString(),
        };

        fastify.log.debug({
          msg: "Analytics event tracked",
          tenant,
          event: eventName,
          data: eventData,
        });

        // Send to analytics provider
        return await provider.trackEvent(eventName, eventData);
      } catch (err) {
        fastify.log.error(err, `Failed to track analytics event ${eventName}`);
        return false;
      }
    },

    // Track page view
    trackPageView: async (path, userId = null, metadata = {}) => {
      return fastify.analytics.trackEvent("page_view", {
        path,
        userId,
        ...metadata,
      });
    },

    // Track API usage
    trackApiUsage: async (
      endpoint,
      method,
      statusCode,
      responseTime,
      userId = null
    ) => {
      return fastify.analytics.trackEvent("api_request", {
        endpoint,
        method,
        statusCode,
        responseTime,
        userId,
      });
    },

    // Track user action (login, logout, etc)
    trackUserAction: async (action, userId, metadata = {}) => {
      return fastify.analytics.trackEvent("user_action", {
        action,
        userId,
        ...metadata,
      });
    },
  });

  // Add request hook to automatically track API usage
  if (analyticsConfig.trackApiRequests) {
    fastify.addHook("onResponse", async (request, reply) => {
      const responseTime = reply.getResponseTime();
      const userId = request.user?.id || null;

      await fastify.analytics.trackApiUsage(
        request.routerPath || request.url,
        request.method,
        reply.statusCode,
        responseTime,
        userId
      );
    });
  }

  // Add request hook to automatically track page views for web routes
  if (analyticsConfig.autoTrackPageViews) {
    fastify.addHook("onResponse", async (request, reply) => {
      // Only track GET requests that don't start with /api or /public
      if (request.method !== "GET") return;
      if (request.url.startsWith("/api/") || request.url.startsWith("/public/"))
        return;

      const userId = request.user?.id || null;
      await fastify.analytics.trackPageView(request.url, userId, {
        referrer: request.headers.referer || request.headers.referrer,
        userAgent: request.headers["user-agent"],
      });
    });
  }

  fastify.log.info(
    `Analytics plugin initialized for tenant ${tenant} using provider ${analyticsConfig.provider}`
  );
}

// Initialize analytics provider based on configuration
function initializeProvider(config, log) {
  const { provider } = config;

  // Simple provider implementations
  const providers = {
    // Google Analytics provider
    "google-analytics": {
      trackEvent: async (eventName, data) => {
        // In a real implementation, send to Google Analytics
        log.debug(`[GA] Tracked ${eventName}: ${JSON.stringify(data)}`);
        return true;
      },
    },

    // Segment provider
    segment: {
      trackEvent: async (eventName, data) => {
        // In a real implementation, send to Segment
        log.debug(`[Segment] Tracked ${eventName}: ${JSON.stringify(data)}`);
        return true;
      },
    },

    // Custom provider (e.g., internal analytics service)
    custom: {
      trackEvent: async (eventName, data) => {
        // In a real implementation, send to custom analytics API
        log.debug(`[Custom] Tracked ${eventName}: ${JSON.stringify(data)}`);
        return true;
      },
    },

    // Default in-memory provider (for development)
    default: {
      events: [],
      trackEvent: async (eventName, data) => {
        const event = { eventName, data, timestamp: new Date().toISOString() };
        this.events.push(event);
        log.debug(`[Default] Tracked ${eventName}: ${JSON.stringify(data)}`);
        return true;
      },
    },
  };

  return providers[provider] || providers.default;
}
```

# src/tenants/tenant1/plugins/tenantSpecificAuth.mjs

```js
// Tenant-specific authentication middleware
export default async function tenantSpecificAuth(fastify, options) {
  const { tenant, config } = options;

  // Get tenant auth configuration
  const authConfig = config.integrations?.sso || {};

  // Implement tenant-specific authentication
  fastify.decorate("tenantAuth", {
    // Authenticate user based on tenant-specific rules
    authenticate: async (request, reply) => {
      // Get token from Authorization header
      const authHeader = request.headers.authorization;
      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        throw { statusCode: 401, message: "Authorization header required" };
      }

      const token = authHeader.substring(7);

      try {
        // Validate the token based on tenant configuration
        if (authConfig.provider === "okta") {
          // In a real app, validate with Okta
          request.user = await validateOktaToken(token, authConfig);
        } else if (authConfig.provider === "auth0") {
          // In a real app, validate with Auth0
          request.user = await validateAuth0Token(token, authConfig);
        } else {
          // Default JWT validation
          request.user = await validateJwtToken(token, tenant);
        }

        if (!request.user) {
          throw { statusCode: 401, message: "Invalid authentication token" };
        }

        // Ensure user has access to this tenant
        if (request.user.tenantId !== tenant) {
          throw {
            statusCode: 403,
            message: "User does not have access to this tenant",
          };
        }

        // Add tenant-specific user info
        request.user.tenantName = config.name;

        return request.user;
      } catch (err) {
        throw {
          statusCode: err.statusCode || 401,
          message: err.message || "Authentication failed",
        };
      }
    },

    // Check if user has specific role
    requireRole: (roles = []) => {
      return async (request, reply) => {
        await fastify.tenantAuth.authenticate(request, reply);

        const userRoles = Array.isArray(request.user.role)
          ? request.user.role
          : [request.user.role];

        const requiredRoles = Array.isArray(roles) ? roles : [roles];

        if (!requiredRoles.some((role) => userRoles.includes(role))) {
          throw {
            statusCode: 403,
            message: `Required role not found. You need one of: ${requiredRoles.join(", ")}`,
          };
        }
      };
    },
  });

  // Register authentication hook
  fastify.addHook("preHandler", async (request, reply) => {
    // Add authenticate method to request for easy use in route handlers
    request.authenticate = async () => {
      return await fastify.tenantAuth.authenticate(request, reply);
    };
  });
}

// Helper functions for token validation

async function validateJwtToken(token, tenant) {
  // In a real app, use JWT library to validate token
  // Example:
  // const decoded = jwt.verify(token, process.env.JWT_SECRET);

  // For this example, we'll just parse a simple token format
  // Don't use this in production!
  try {
    const base64Payload = token.split(".")[1];
    const payload = JSON.parse(
      Buffer.from(base64Payload, "base64").toString("utf8")
    );

    // Check token expiration
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
      throw new Error("Token expired");
    }

    // Check tenant ID
    if (payload.tenantId !== tenant) {
      throw new Error("Token is for a different tenant");
    }

    return {
      id: payload.id,
      email: payload.email,
      role: payload.role,
      tenantId: payload.tenantId,
    };
  } catch (err) {
    throw { statusCode: 401, message: "Invalid token" };
  }
}

async function validateOktaToken(token, config) {
  // In a real app, validate token with Okta API
  // Example pseudocode:
  // const response = await fetch(`${config.tenantUrl}/oauth2/default/v1/introspect`, {
  //   method: 'POST',
  //   headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  //   body: `token=${token}&client_id=${config.clientId}`
  // });

  // For this example, we'll just simulate a valid response
  return {
    id: "okta-user-id",
    email: "user@example.com",
    role: "user",
    tenantId: "tenant1",
    oktaId: "okta-specific-id",
  };
}

async function validateAuth0Token(token, config) {
  // In a real app, validate token with Auth0 API
  // Similar to Okta validation

  // For this example, we'll just simulate a valid response
  return {
    id: "auth0-user-id",
    email: "user@example.com",
    role: "user",
    tenantId: "tenant1",
    auth0Id: "auth0-specific-id",
  };
}
```

# src/tenants/tenant1/database/migrations/001_initial_schema.sql

```sql
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY,
  tenant_id VARCHAR(100) NOT NULL,
  first_name VARCHAR(100) NOT NULL,
  last_name VARCHAR(100) NOT NULL,
  email VARCHAR(255) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  role VARCHAR(50) NOT NULL DEFAULT 'user',
  status VARCHAR(50) NOT NULL DEFAULT 'active',
  metadata JSONB NULL,
  last_login_at TIMESTAMP WITH TIME ZONE NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
  UNIQUE(tenant_id, email)
);
```

# src/tenants/tenant1/plugins/auditLogger.mjs

```js
// Audit logging hook for tenant1
export default async function auditLoggerHook(fastify, options) {
  const { tenant, config } = options;

  // Check if audit logging is enabled for this tenant
  const auditConfig = config.compliance?.auditLogging || { enabled: false };

  if (!auditConfig.enabled) {
    fastify.log.info(`Audit logging disabled for tenant ${tenant}`);
    return;
  }

  // Add the audit logger service
  fastify.decorate(
    "auditLog",
    async (action, resourceType, resourceId, details, user = null) => {}
  );

  // Add hooks to automatically log certain events
  if (auditConfig.autoLogRequests) {
    // Log write operations (POST, PUT, DELETE)
    fastify.addHook("onRequest", async (request, reply) => {
      const method = request.method;
      if (["POST", "PUT", "PATCH", "DELETE"].includes(method)) {
        request.shouldAudit = true;
      }
    });

    fastify.addHook("onResponse", async (request, reply) => {
      if (!request.shouldAudit) return;

      // Only log successful requests
      if (reply.statusCode >= 200 && reply.statusCode < 300) {
        const userId = request.user?.id;
        const method = request.method;
        const path = request.routerPath || request.url;

        // Determine action and resource type from path
        const pathParts = path.split("/").filter(Boolean);
        let action = method.toLowerCase();
        let resourceType = pathParts[0] || "unknown";
        let resourceId = pathParts[1] || "none";

        // Map method to action
        switch (method) {
          case "POST":
            action = "create";
            break;
          case "PUT":
          case "PATCH":
            action = "update";
            break;
          case "DELETE":
            action = "delete";
            break;
        }

        // Create details object
        const details = {
          method,
          path,
          statusCode: reply.statusCode,
          ip: request.ip,
          userAgent: request.headers["user-agent"],
        };

        // Add request body for logging if configured and not sensitive
        if (auditConfig.includeRequestBody && !path.includes("password")) {
          details.body = request.body;
        }

        await fastify.auditLog(
          action,
          resourceType,
          resourceId,
          details,
          request.user
        );
      }
    });
  }

  fastify.log.info(`Audit logging initialized for tenant ${tenant}`);
}
```

# src/tenants/tenant1/test/routes.users.test.mjs

```js
import { test } from "tap";
import { build } from "../helper.js";
import jwt from "jsonwebtoken";

// Create test JWT token
function generateToken(user) {
  return jwt.sign(user, "test-secret", { expiresIn: "1h" });
}

// Mock user data
const testUser = {
  id: "12345678-1234-1234-1234-123456789012",
  email: "test@example.com",
  firstName: "Test",
  lastName: "User",
  role: "admin",
  tenantId: "tenant1",
};

// Tests for user routes
test("User routes", async (t) => {
  // Build test app with mocked dependencies
  const app = await build(t, {
    tenant: "tenant1",
    mockDb: true,
  });

  // Mock user service
  app.decorate("services", {
    userService: {
      getUsers: async () => ({
        users: [testUser],
        pagination: { total: 1, limit: 20, offset: 0, hasMore: false },
      }),
      getUserById: async (tenantId, id) => {
        return id === testUser.id ? testUser : null;
      },
      createUser: async (tenantId, userData) => ({
        ...testUser,
        ...userData,
        id: "new-user-id",
      }),
      updateUser: async (tenantId, id, userData) => {
        return id === testUser.id ? { ...testUser, ...userData } : null;
      },
      deleteUser: async (tenantId, id) => {
        return id === testUser.id;
      },
      authenticate: async (tenantId, email, password) => {
        return email === testUser.email && password === "password"
          ? { token: "test-token", user: testUser }
          : null;
      },
    },
  });

  // Create auth headers
  const token = generateToken(testUser);
  const headers = {
    authorization: `Bearer ${token}`,
  };

  // Test GET /users endpoint
  t.test("GET /users returns list of users", async (t) => {
    const response = await app.inject({
      method: "GET",
      url: "/tenant1/users",
      headers,
    });

    t.equal(response.statusCode, 200);
    t.same(JSON.parse(response.body).users, [testUser]);
  });

  // Test GET /users/:id endpoint
  t.test("GET /users/:id returns a single user", async (t) => {
    const response = await app.inject({
      method: "GET",
      url: `/tenant1/users/${testUser.id}`,
      headers,
    });

    t.equal(response.statusCode, 200);
    t.same(JSON.parse(response.body).user, testUser);
  });

  // Test GET /users/:id with invalid ID
  t.test("GET /users/:id returns 404 for invalid ID", async (t) => {
    const response = await app.inject({
      method: "GET",
      url: "/tenant1/users/invalid-id",
      headers,
    });

    t.equal(response.statusCode, 404);
  });

  // Test POST /users endpoint
  t.test("POST /users creates a new user", async (t) => {
    const newUser = {
      firstName: "New",
      lastName: "User",
      email: "new@example.com",
      password: "password123",
    };

    const response = await app.inject({
      method: "POST",
      url: "/tenant1/users",
      headers,
      payload: newUser,
    });

    t.equal(response.statusCode, 201);
    t.match(JSON.parse(response.body).user, {
      firstName: "New",
      lastName: "User",
      email: "new@example.com",
    });
  });

  // Test PUT /users/:id endpoint
  t.test("PUT /users/:id updates a user", async (t) => {
    const userData = {
      firstName: "Updated",
      lastName: "User",
    };

    const response = await app.inject({
      method: "PUT",
      url: `/tenant1/users/${testUser.id}`,
      headers,
      payload: userData,
    });

    t.equal(response.statusCode, 200);
    t.match(JSON.parse(response.body).user, {
      firstName: "Updated",
      lastName: "User",
    });
  });

  // Test DELETE /users/:id endpoint
  t.test("DELETE /users/:id deletes a user", async (t) => {
    const response = await app.inject({
      method: "DELETE",
      url: `/tenant1/users/${testUser.id}`,
      headers,
    });

    t.equal(response.statusCode, 200);
    t.same(JSON.parse(response.body), {
      success: true,
      message: "User deleted successfully",
    });
  });

  // Test user login
  t.test("POST /users/login authenticates a user", async (t) => {
    const loginData = {
      email: testUser.email,
      password: "password",
    };

    const response = await app.inject({
      method: "POST",
      url: "/tenant1/users/login",
      payload: loginData,
    });

    t.equal(response.statusCode, 200);
    t.has(JSON.parse(response.body), { token: "test-token" });
  });

  // Test user login with invalid credentials
  t.test("POST /users/login fails with invalid credentials", async (t) => {
    const loginData = {
      email: testUser.email,
      password: "wrong-password",
    };

    const response = await app.inject({
      method: "POST",
      url: "/tenant1/users/login",
      payload: loginData,
    });

    t.equal(response.statusCode, 401);
  });
});
```

# src/tenants/tenant1/lib/validators.mjs

```js
// Custom validation helpers for tenant1
export const validators = {
  // Validate email format
  isValidEmail: (email) => {
    const regex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return regex.test(email);
  },

  // Validate password strength
  isStrongPassword: (password) => {
    if (!password || password.length < 8) return false;

    // Check for at least one uppercase, lowercase, number, and special character
    const hasUppercase = /[A-Z]/.test(password);
    const hasLowercase = /[a-z]/.test(password);
    const hasNumber = /[0-9]/.test(password);
    const hasSpecial = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password);

    return hasUppercase && hasLowercase && hasNumber && hasSpecial;
  },

  // Validate phone number format (simplified)
  isValidPhone: (phone) => {
    const regex = /^\+?[1-9]\d{9,14}$/;
    return regex.test(phone);
  },

  // Sanitize input to prevent XSS
  sanitizeHtml: (input) => {
    if (!input) return "";

    // Simple sanitization - replace <, >, &, ", ' with HTML entities
    return input
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  },
};

export const formatters = {
  // Format date according to tenant preferences
  formatDate: (date, format = "YYYY-MM-DD") => {
    if (!date) return "";

    const d = new Date(date);

    // Simple formatter (in production use a library like date-fns)
    const year = d.getFullYear();
    const month = String(d.getMonth() + 1).padStart(2, "0");
    const day = String(d.getDate()).padStart(2, "0");

    return format.replace("YYYY", year).replace("MM", month).replace("DD", day);
  },

  // Format currency according to tenant preferences
  formatCurrency: (amount, currency = "USD", locale = "en-US") => {
    return new Intl.NumberFormat(locale, {
      style: "currency",
      currency: currency,
    }).format(amount);
  },

  // Format phone number
  formatPhone: (phone, format = "US") => {
    if (!phone) return "";

    // Simple US phone formatter
    if (format === "US") {
      const cleaned = ("" + phone).replace(/\D/g, "");
      const match = cleaned.match(/^(\d{3})(\d{3})(\d{4})$/);
      if (match) {
        return `(${match[1]}) ${match[2]}-${match[3]}`;
      }
    }

    return phone;
  },
};

export default {
  validators,
  formatters,
};
```

```
Setup Instructions for tenant1

Create the tenant directory structure:
Copymkdir -p src/tenants/tenant1/{routes,schemas,services,plugins,middleware,models,database/{migrations,seeds},lib,hooks,test/{routes,services}}

Implement the core configuration files:

Create config.js with tenant settings
Optionally create index.mjs if you need a custom tenant ID


Implement database migrations:

Create SQL files in database/migrations/
Run migrations using your database migration tool


Implement schemas:

Define JSON schemas for validation in schemas/


Implement services:

Create service classes in services/ for business logic


Implement routes:

Define API endpoints in routes/


Optional: Implement tenant-specific plugins:

Create plugins in plugins/ for tenant-specific functionality


Optional: Implement tenant-specific hooks and middleware:

Create hooks in hooks/
Create middleware in middleware/


Optional: Implement tests:

Create tests in test/ for routes and services

14. Multi-Tenant Best Practices

Data Isolation: Ensure complete data isolation between tenants by:

Using tenant_id in every database query
Including tenant context in all service methods
Validating tenant access in route handlers


Security: Implement tenant-specific security measures:

Use tenant-specific authentication providers if needed
Implement custom authorization rules per tenant
Set up tenant-specific rate limiting


Configuration: Make tenant configuration flexible:

Allow overriding global settings
Use environment variables for sensitive data
Support tenant-specific feature flags


Customization: Allow for tenant-specific customization:

Custom branding and themes
Custom email templates
Tenant-specific business rules


Performance: Optimize for multi-tenant performance:

Consider connection pooling per tenant
Cache tenant-specific data
Monitor performance per tenant
```
