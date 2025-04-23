// User routes for tenant1
export default async function userRoutes(fastify, options) {
  const { tenant, config } = options;
  const { userService } = fastify.services;

  // Require authentication for all user routes
  const authHook = async (request, reply) => {
    if (!request.user) {
      reply.code(401).send({
        error: "Unauthorized",
        message: "Authentication required",
      });
    }
  };

  // Get all users
  fastify.get(
    "/users",
    {
      onRequest: authHook,
      schema: {
        response: {
          200: fastify.getSchema("userListResponse"),
        },
      },
    },
    async (request, reply) => {
      const users = await userService.getUsers(request.tenantId);
      return { users };
    }
  );

  // Get user by ID
  fastify.get(
    "/users/:id",
    {
      onRequest: authHook,
      schema: {
        params: {
          type: "object",
          required: ["id"],
          properties: {
            id: { type: "string" },
          },
        },
        response: {
          200: fastify.getSchema("userResponse"),
        },
      },
    },
    async (request, reply) => {
      const user = await userService.getUserById(
        request.tenantId,
        request.params.id
      );

      if (!user) {
        reply.code(404).send({
          error: "Not Found",
          message: "User not found",
        });
        return;
      }

      return { user };
    }
  );

  // Create user
  fastify.post(
    "/users",
    {
      onRequest: authHook,
      schema: {
        body: fastify.getSchema("userCreate"),
        response: {
          201: fastify.getSchema("userResponse"),
        },
      },
    },
    async (request, reply) => {
      const user = await userService.createUser(request.tenantId, request.body);
      reply.code(201);
      return { user };
    }
  );

  // Update user
  fastify.put(
    "/users/:id",
    {
      onRequest: authHook,
      schema: {
        params: {
          type: "object",
          required: ["id"],
          properties: {
            id: { type: "string" },
          },
        },
        body: fastify.getSchema("userUpdate"),
        response: {
          200: fastify.getSchema("userResponse"),
        },
      },
    },
    async (request, reply) => {
      const user = await userService.updateUser(
        request.tenantId,
        request.params.id,
        request.body
      );

      if (!user) {
        reply.code(404).send({
          error: "Not Found",
          message: "User not found",
        });
        return;
      }

      return { user };
    }
  );

  // Delete user
  fastify.delete(
    "/users/:id",
    {
      onRequest: authHook,
      schema: {
        params: {
          type: "object",
          required: ["id"],
          properties: {
            id: { type: "string" },
          },
        },
        response: {
          200: {
            type: "object",
            properties: {
              success: { type: "boolean" },
              message: { type: "string" },
            },
          },
        },
      },
    },
    async (request, reply) => {
      const deleted = await userService.deleteUser(
        request.tenantId,
        request.params.id
      );

      if (!deleted) {
        reply.code(404).send({
          error: "Not Found",
          message: "User not found",
        });
        return;
      }

      return {
        success: true,
        message: "User deleted successfully",
      };
    }
  );
}
