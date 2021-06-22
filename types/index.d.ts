// TypeScript Version: 4.3

import express = require('express');

export = expressJwtScope;

/** Creates a factory function that returns request handling middleware. */
declare function expressJwtScope(options?: expressJwtScope.Options): expressJwtScope.RequestHandlerFactory;

declare namespace expressJwtScope {
  /** Configuration options. */
  interface Options {
    adminKey?: string | string[];
    claimDelimiter?: string;
    claimScopeDelimiter?: string;
    scopeKey?: string | string[];
    tokenKey?: string | string[];
  }

  /** Data available to a custom permission checker. */
  interface PermissionCheckHelpers {
    error: (message: string) => never;
    req: express.Request;
    claimDelimiter: string;
    claimScopeDelimiter: string;
    isAdmin?: boolean;
    originScope: string | string[];
    token: object;
  }

  /** Call signature for custom permission checker. */
  interface PermissionCheckCallback {
    (scope?: string[][], helpres?: PermissionCheckHelpers): boolean;
  }

  /** Argument type for the middleware factory function. */
  type RequestedPermission = string | PermissionCheckCallback;

  /** Request handling middleware. */
  interface RequestHandler extends express.RequestHandler {
    not: (permission: RequestedPermission, ...restPermissions: RequestedPermission[]) => RequestHandler;
    or: (permission: RequestedPermission, ...restPermissions: RequestedPermission[]) => RequestHandler;
    promisify: () => express.RequestHandler;
  }

  /** Produces request handler that check the access token for requested permissions. */
  interface RequestHandlerFactory {
    (...permissions: RequestedPermission[]): RequestHandler;
  }
}
