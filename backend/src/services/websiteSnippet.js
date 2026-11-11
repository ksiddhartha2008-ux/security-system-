/**
 * The install snippet is generated from the same API the SDK exposes. A test in
 * backend/tests/website-sdk.test.mjs writes this string to a file and runs
 * `node --check` on it, so the dashboard cannot drift into invalid code.
 */
export function installSnippet(site) {
  const endpoint = 'https://YOUR-SECUREFLOW-HOST/v1/ingest/website-events';
  return `import express from 'express';
import { SecureFlow } from 'secureflow-sdk-node';

const app = express();
app.use(express.json());

const sf = new SecureFlow({
  apiKey: process.env.SECUREFLOW_API_KEY,
  endpoint: '${endpoint}',
  actorIdMode: 'hash',
  actorPepper: process.env.SECUREFLOW_ACTOR_PEPPER,
});

// Call this from your existing sign-in handler, before you send the response.
app.post('/login', (req, res) => {
  const ctx = sf.requestContext(req);
  const ok = req.body.password === 'the-real-check-happens-in-your-code';
  sf.track({
    type: ok ? 'auth.login_succeeded' : 'auth.login_failed',
    actor: { id: req.body.email, id_mode: 'hash' },
    client: { ip: ctx.ip, user_agent: ctx.user_agent },
    request: { host: ctx.host, method: ctx.method, path: ctx.path, status: ok ? 200 : 401 },
  });
  res.status(ok ? 200 : 401).json({ ok });
});

app.listen(3000, () => {
  console.log('Example site listening on port 3000 for ${site.hostname}');
});
`;
}
