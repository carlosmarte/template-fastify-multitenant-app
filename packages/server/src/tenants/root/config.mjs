
export default {
  id: "tenant1",
  name: "Customer Portal",
  description: "Customer-facing portal for service access and management",
  active: true,
  version: "1.0.0",
  settings: { },
  features: { },
  integrations: {},
  database: {
    name: "tenant1_db",
    schema: "tenant1",
    maxConnections: 10,
  },
};
