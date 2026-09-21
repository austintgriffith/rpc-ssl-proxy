import { validateRpcRequest } from './requestValidator.js';
import { createLogsAccess } from './logsAccess.js';

// Shared by the production listener and HTTP integration tests.
export function registerRpcRoutes(app, { legacyHandler, ...access }) {
  app.post(['/', '/v1/:key'], validateRpcRequest, createLogsAccess(access), legacyHandler);
}
