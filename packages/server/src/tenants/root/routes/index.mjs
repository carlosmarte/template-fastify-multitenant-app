// Main routes for tenant1
export default async function routes(app, options) {
  const { tenant, config, fastify } = options;

  fastify.get("/", async (request, reply) => {
    return {
      status: "ok",
      timestamp: new Date().toISOString(),
    };
  });

  fastify.get("/health", async (request, reply) => {
    return {
      status: "ok",
      timestamp: new Date().toISOString(),
    };
  });

  fastify.setNotFoundHandler((request, reply) => {
    reply.code(404).send({
      error: "Not Found",
      message: `The requested resource doesn't exist on ${config.name}`,
      tenant: config.id,
    });
  });

  app.get(
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
              features: { type: "object" },
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
        features: config.features,
      };
    }
  );
}
