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
    /** Character separeting permissions if granted permissions described as a string. */
    claimDelimiter?: string;
    /** Character separating permission's name and scope. */
    claimScopeDelimiter?: string;
    /** Path to granted permissions inside the access token. */
    scopeKey?: string | string[];
    /** Path to the access token in HTTP request object. */
    tokenKey?: string | string[];
  }

  /** Data available to a custom permission checker. */
  interface Helper {
    /** Throws ForbiddenError with provided error message. */
    error: (message: string) => never;
    /** Reference to the HTTP request object. */
    req: express.Request;
    /** Character separeting permissions if granted permissions described as a string. */
    claimDelimiter: string;
    /** Character separating permission's name and scope. */
    claimScopeDelimiter: string;
    /** Whether or not token possesses admin claim. */
    isAdmin?: boolean;
    /** Copy of granted permissions claim. */
    originScope: string | string[];
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
}
