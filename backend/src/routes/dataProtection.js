import { Router } from 'express';
import { asyncHandler, ok } from '../lib/http.js';
import { requireAuth } from '../lib/auth.js';
import { dataProtectionOverview } from '../services/dataProtection.js';

/** Read only protection summary for the signed in workspace. */
const router = Router();
router.use(requireAuth);

router.get('/overview', asyncHandler(async (req, res) => ok(res, dataProtectionOverview(req.user.orgId))));

export default router;
