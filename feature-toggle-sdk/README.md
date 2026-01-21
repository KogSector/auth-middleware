# @confuse/feature-toggle-sdk

TypeScript SDK for the ConFuse Feature Toggle service.

## Installation

```bash
npm install @confuse/feature-toggle-sdk
```

## Quick Start

```typescript
import { 
  initToggleClient, 
  isToggleEnabled, 
  requireToggle 
} from '@confuse/feature-toggle-sdk';

// Initialize once at app startup
initToggleClient({
  serviceUrl: process.env.FEATURE_TOGGLE_SERVICE_URL || 'http://localhost:3099',
  serviceName: 'my-service',
  cacheTtlMs: 5000,      // Cache for 5 seconds (default)
  timeoutMs: 2000,       // 2 second timeout (default)
  retryAttempts: 2,      // Retry twice on failure (default)
  defaultEnabled: false, // Default when service unavailable
});
```

## Usage

### Check Toggle State

```typescript
import { isToggleEnabled, getToggleClient } from '@confuse/feature-toggle-sdk';

// Simple check
if (await isToggleEnabled('myFeature')) {
  // Feature is enabled
}

// Using client directly
const client = getToggleClient();

// Get toggle with full details
const toggle = await client.getToggle('myFeature');
console.log(toggle?.description);

// Get all toggles
const allToggles = await client.getAllToggles();

// Get toggles by category
const authToggles = await client.getTogglesByCategory('authentication');

// Check multiple at once
const states = await client.areEnabled(['featureA', 'featureB']);
```

### Express Middleware

```typescript
import express from 'express';
import { 
  initToggleClient,
  requireToggle, 
  attachToggles,
  checkAuthBypass 
} from '@confuse/feature-toggle-sdk';

const app = express();

// Initialize client
initToggleClient({
  serviceUrl: 'http://feature-toggle:3099',
  serviceName: 'api-backend',
});

// Block route when toggle is disabled (returns 404)
app.get('/beta-feature', 
  requireToggle({ toggle: 'betaFeature' }), 
  (req, res) => {
    res.json({ message: 'Beta feature!' });
  }
);

// Custom behavior when disabled
app.get('/optional-feature',
  requireToggle({ 
    toggle: 'optionalFeature',
    onDisabled: 'skip', // Continue to next handler
    // Or: onDisabled: (req, res, next) => { ... }
  }),
  (req, res) => {
    res.json({ message: 'Feature available' });
  }
);

// Attach toggle states to request
app.use(attachToggles(['featureA', 'featureB', 'featureC']));

app.get('/api', (req, res) => {
  // Access toggle states from request
  if (req.toggles?.featureA) {
    // Feature A logic
  }
  res.json({ toggles: req.toggles });
});

// Check auth bypass for development
app.use(checkAuthBypass());

app.use((req, res, next) => {
  if (req.bypassUser) {
    // Use demo user instead of real authentication
    req.user = req.bypassUser;
  }
  next();
});
```

### Custom Client Instance

```typescript
import { createToggleClient } from '@confuse/feature-toggle-sdk';

// Create a dedicated client instance
const client = createToggleClient({
  serviceUrl: 'http://feature-toggle:3099',
  serviceName: 'my-worker',
  onServiceUnavailable: (error) => {
    console.error('Feature toggle service down:', error);
  },
});

// Use the client
const enabled = await client.isEnabled('myFeature');
```

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `serviceUrl` | `string` | **required** | Base URL of the feature toggle service |
| `serviceName` | `string` | `'unknown-service'` | Service name for audit logging |
| `cacheTtlMs` | `number` | `5000` | Cache TTL in milliseconds |
| `timeoutMs` | `number` | `2000` | Request timeout in milliseconds |
| `retryAttempts` | `number` | `2` | Number of retry attempts |
| `retryDelayMs` | `number` | `500` | Delay between retries |
| `defaultEnabled` | `boolean` | `false` | Default when toggle not found |
| `onServiceUnavailable` | `function` | `undefined` | Callback on service error |

## Cache Management

```typescript
const client = getToggleClient();

// Invalidate all cached data
client.invalidateCache();

// Invalidate specific toggle
client.invalidateToggle('myFeature');
```

## Error Handling

The SDK is designed to fail gracefully:

- Returns `defaultEnabled` when toggle not found
- Returns `defaultEnabled` when service unavailable
- Logs warnings but doesn't throw errors
- Middleware continues on errors (fail-open)

For critical toggles, you can handle errors explicitly:

```typescript
const client = createToggleClient({
  serviceUrl: 'http://feature-toggle:3099',
  onServiceUnavailable: (error) => {
    // Alert, log to monitoring, etc.
    alertOps('Feature toggle service unavailable!');
  },
});
```
