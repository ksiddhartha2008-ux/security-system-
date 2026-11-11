import express from 'express';
import { SecureFlow } from 'secureflow-sdk-node';

/**
 * This example is checked by the SDK test suite with `node --check`. It is the
 * same shape the dashboard generates, with a placeholder endpoint.
 */
export function registerLoginRoute(app, sf) {
  app.post('/login', (req, res) => {
    const context = sf.requestContext(req);
    const accepted = req.body?.password === 'replace-with-your-own-check';
    sf.track({
      type: accepted ? 'auth.login_succeeded' : 'auth.login_failed',
      actor: { id: String(req.body?.email ?? 'unknown'), id_mode: 'hash' },
      client: { ip: context.ip, user_agent: context.user_agent },
      request: { host: context.host, method: context.method, path: context.path, status: accepted ? 200 : 401 },
    });
    res.status(accepted ? 200 : 401).json({ ok: accepted });
  });
}

export function createSdk() {
  return new SecureFlow({
    apiKey: process.env.SECUREFLOW_API_KEY,
    endpoint: process.env.SECUREFLOW_ENDPOINT ?? 'https://secureflow.example.com/v1/ingest/website-events',
    actorIdMode: 'hash',
    actorPepper: process.env.SECUREFLOW_ACTOR_PEPPER,
  });
}

if (process.argv[1] && process.argv[1].endsWith('login-route.mjs')) {
  const app = express();
  app.use(express.json());
  registerLoginRoute(app, createSdk());
  app.listen(3000, () => console.log('Example site listening on port 3000'));
}
