// TypeScript Version: 4.3

import express = require('express');

export = expressJwtScope;

/** Creates a factory function that returns request handling middleware. */
declare function expressJwtScope(options?: expressJwtScope.Options): expressJwtScope.Factory;

declare namespace expressJwtScope {
  /** Configuration options. */
  interface Options {
    /** Path to admin claim inside the access token or a callback. */
    adminKey?: string | string[] | Checker;
    /** Character separeting permissions if granted permissions described as a string, default is `,`. */
    claimDelimiter?: string;
    /** Character separating permission's name and scope, default is `:`. */
    claimScopeDelimiter?: string;
    /** Set to `false` to skip permission check for an unauthorized users, default is `true`. */
    credentialsRequired?: boolean;
    /** Path to attach permission check methods to the `req` object, default is `permissions`. */
    requestProperty?: string | string[];
    /** Path to granted permissions inside the access token, default is `scope`. */
    scopeKey?: string | string[];
    /** Path to the access token in HTTP request object, default is `user`. */
    tokenKey?: string | string[];
  }

  /** Data available to a custom permission checker. */
  interface Helper {
    /** Reference to the HTTP request object. */
    req: express.Request;
    /** Whether or not token possesses admin claim. */
    isAdmin?: boolean;
    /** Copy of the access token. */
    token: object;
  }

  /** Call signature for custom permission checker. */
  interface Checker {
    (scope: string[][], helpres: Helper): boolean;
  }

  /** Request handling middleware. */
  interface RequestHandler extends express.RequestHandler {
    /** Add negation of requested permission using logical `and` operator. */
    not: (
      permission: string | Checker,
      ...restPermissions: Array<string | Checker>
    ) => RequestHandler;
    /** Add alternative set of permissions to check. */
    or: (
      permission: string | Checker,
      ...restPermissions: Array<string | Checker>
    ) => RequestHandler;
    promisify: () => express.RequestHandler;
  }

  /** Function produces request handler that check the access token for requested permissions. */
  interface Factory {
    (...permissions: Array<string | Checker>): RequestHandler;
  }

  /** Thrown if permission check failed. */
  class ForbiddenError extends Error {
    expose: boolean;
    message: string;
    name: 'ForbiddenError';
    status: number;
    statusCode: number;

    constructor(message?: string);
  }

  /** Thrown if the access token not found. */
  class UnauthorizedError extends Error {
    expose: boolean;
    message: string;
    name: 'UnauthorizedError';
    status: number;
    statusCode: number;

    constructor(message?: string);
  }
}

declare global {
  namespace Express {
    interface Permissions {
      /** Returns `true` if has admin claim or requested permission. */
      allowed(permission: string | expressJwtScope.Checker): Promise<boolean>;
      /** Returns `true` if the access token has admin claim. */
      isAdmin(): boolean;
      /** Returns `true` if the access token has requested permission. */
      hasPermission(permission: string | expressJwtScope.Checker): Promise<boolean>;
    }

    interface Request {
      permissions?: Permissions;
    }
  }
}
