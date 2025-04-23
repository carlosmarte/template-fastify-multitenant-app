Project Structure

```
/
├── main.mjs               # Main entry point (this file)
├── src/
│   ├── plugins/           # Core plugins
│   │   ├── exception/     # Error handling
│   │   ├── logger/        # Logging configuration
│   │   └── ...
│   └── tenants/           # Tenant-specific code
│       ├── tenant1/       # First tenant
│       │   ├── config.js  # Tenant configuration
│       │   ├── index.mjs  # Optional custom tenant name
│       │   ├── plugins/   # Tenant-specific plugins
│       │   ├── routes/    # Tenant-specific routes
│       │   ├── schemas/   # JSON schemas
│       │   └── services/  # Business logic
│       └── tenant2/       # Second tenant
└── package.json
```
