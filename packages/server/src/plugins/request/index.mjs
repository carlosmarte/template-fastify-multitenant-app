import fastifySensible from "@fastify/sensible";
import fastifyEtag from "@fastify/etag";
import fastifyHelmet from "@fastify/helmet";
import fastifyRateLimit from "@fastify/rate-limit";
import fastifyCors from "@fastify/cors";
import fastifyCompress from "@fastify/compress";
import fastifyFormbody from "@fastify/formbody";
import fastifyMultipart from "@fastify/multipart";

export const requestPlugin = async (fastify, options) => {
  fastify.register(fastifySensible);
  fastify.register(fastifyEtag);
  fastify.register(fastifyHelmet);
  fastify.register(fastifyRateLimit, {
    max: 100,
    timeWindow: "1 minute",
  });
  fastify.register(fastifyCors, {
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE"],
    hook: "preHandler",
    allowedHeaders: ["Content-Type", "Authorization"],
    exposedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
    maxAge: 3600,
    delegator: (req, callback) => {
      if (options.corsDelegators) {
        callback(options.corsDelegators[0], options.corsDelegators[0]);
      } else if (options.corsUseOrigin) {
        const origin = req.headers.origin;
        if (origin) {
          callback(null, true);
        } else {
          callback(new Error("Origin not allowed"));
        }
      } else if (options.corsUseAnyHost) {
        callback(null, {
          origin: "*",
          methods: ["GET", "POST", "PUT", "DELETE"],
          allowedHeaders: ["Content-Type", "Authorization"],
          exposedHeaders: ["Content-Type", "Authorization"],
          credentials: true,
          maxAge: 3600,
        });
      } else {
        callback(null, {
          origin: true,
          credentials: true,
        });
      }
    },
  });
  fastify.register(fastifyCompress);
  fastify.register(fastifyFormbody);
  fastify.register(fastifyMultipart);
};

export default requestPlugin;
