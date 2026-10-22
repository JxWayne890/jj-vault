import { createRelay } from '../src/relay.mjs';

// No secrets, database connections or vault state are retained between requests.
export default {
  fetch(request) {
    return createRelay({ env: process.env })(request);
  }
};
