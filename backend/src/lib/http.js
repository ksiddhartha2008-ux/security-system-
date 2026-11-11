import express from 'express';
import { ZodError } from 'zod';

export class ApiError extends Error {
  constructor(status, code, message, details) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

export const badRequest = (message, details) => new ApiError(400, 'bad_request', message, details);
export const unauthorized = (message = 'Authentication required') => new ApiError(401, 'unauthorized', message);
export const forbidden = (message = 'You do not have permission to perform this action') => new ApiError(403, 'forbidden', message);
export const notFound = (message = 'Resource not found') => new ApiError(404, 'not_found', message);
export const conflict = (message) => new ApiError(409, 'conflict', message);
export const tooMany = (message = 'Too many requests') => new ApiError(429, 'rate_limited', message);

/** Wrap async route handlers so thrown errors reach the error middleware. */
export const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

export function ok(res, data, meta) {
  const body = { data };
  if (meta) body.meta = meta;
  return res.json(body);
}

export function created(res, data) {
  return res.status(201).json({ data });
}

export function pageParams(req, { maxLimit = 100, defaultLimit = 20 } = {}) {
  const limit = Math.min(Math.max(Number.parseInt(req.query.limit ?? defaultLimit, 10) || defaultLimit, 1), maxLimit);
  const page = Math.max(Number.parseInt(req.query.page ?? 1, 10) || 1, 1);
  return { limit, page, offset: (page - 1) * limit };
}

export function paginated(res, items, total, { page, limit }) {
  return res.json({
    data: items,
    meta: {
      page,
      limit,
      total,
      totalPages: Math.max(Math.ceil(total / limit), 1),
      hasNext: page * limit < total,
    },
  });
}

export function validate(schema, payload) {
  const result = schema.safeParse(payload);
  if (!result.success) {
    throw new ApiError(400, 'validation_failed', 'Request validation failed', formatZod(result.error));
  }
  return result.data;
}

export function formatZod(error) {
  return error.issues.map((issue) => ({
    path: issue.path.join('.') || '(root)',
    message: issue.message,
  }));
}

/** Consistent error envelope + no stack traces in responses. */
export function errorHandler(err, req, res, _next) {
  const requestId = req.requestId ?? null;
  if (err instanceof ZodError) {
    return res.status(400).json({ error: { code: 'validation_failed', message: 'Request validation failed', details: formatZod(err), request_id: requestId } });
  }
  if (err instanceof ApiError) {
    if (err.status === 429) res.setHeader('Retry-After', '60');
    return res.status(err.status).json({
      error: { code: err.code, message: err.message, details: err.details, request_id: requestId },
    });
  }
  if (err?.type === 'entity.too.large') {
    return res.status(413).json({ error: { code: 'payload_too_large', message: 'Request body exceeds the allowed size', request_id: requestId } });
  }
  console.error('[error]', req.method, req.originalUrl, err);
  return res.status(500).json({
    error: { code: 'internal_error', message: 'Something went wrong on our side. The failure was logged.', request_id: requestId },
  });
}

export function notFoundHandler(req, res) {
  res.status(404).json({ error: { code: 'not_found', message: `No API route matches ${req.method} ${req.path}` } });
}

export const json = express.json;
