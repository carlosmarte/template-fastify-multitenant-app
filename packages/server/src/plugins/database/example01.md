```js
// In tenant loading, create tenant-specific connections
const dbConfig = config.database || {};
const tenantDb = createTenantDatabase(customTenantId, dbConfig);
contexts.tenants[customTenantId].db = tenantDb;

// In routes
fastify.get("/users", async (request, reply) => {
  // Use the tenant-specific database connection
  const db = request.tenant.db;
  const users = await db.query("SELECT * FROM users");
  return { users };
});
```
