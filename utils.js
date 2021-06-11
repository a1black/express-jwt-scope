'use strict'

const { ExpressJwtScopeError, InternalServerError } = require('./errors')

/**
 * Returns deep-copy of JSON serialazible `origin` object.
 */
function deepCopy(origin) {
  return typeof origin === 'object'
    ? JSON.parse(JSON.stringify(origin))
    : origin
}

/** Returns `true` if argument is a function. */
function isFunction(value) {
  return typeof value === 'function'
}

/** Returns `true` if argument is a string. */
function isString(value) {
  return typeof value === 'string' || value instanceof String
}

/**
 * Returns module configuration object formed from `options` and default values.
 */
function moduleArgv(options) {
  let {
    adminClaimEnabled,
    claimDelimiter,
    claimScopeDelimiter,
    scopeRequired,
    scopeKey = 'scope',
    tokenKey = 'user'
  } = options || {}
  const claimCharset = '[a-zA-Z0-9_]'
  const delimiterRegex = /[-!"#$%&'()+,./:;<=>?@[\]^`{|}~ ]/

  const validDelimiter = delimiter =>
    isString(delimiter) &&
    delimiter.length === 1 &&
    delimiterRegex.test(delimiter)
  const delimiterError = (name, value) =>
    new ExpressJwtScopeError(
      `${name} must be unescaped ASCII punctuation character` +
        ` (except '*' and '_') or space, got '${value}`,
      'invalid_config_option',
      { name, value }
    )

  if (claimDelimiter && !validDelimiter(claimDelimiter)) {
    throw delimiterError('claimDelimiter', claimDelimiter)
  } else if (claimScopeDelimiter && !validDelimiter(claimScopeDelimiter)) {
    throw delimiterError('claimScopeDelimiter', claimScopeDelimiter)
  }

  adminClaimEnabled = adminClaimEnabled === true
  scopeRequired = scopeRequired !== false

  claimDelimiter = claimDelimiter || ','
  claimScopeDelimiter = claimScopeDelimiter || ':'
  if (claimDelimiter === claimScopeDelimiter) {
    throw new ExpressJwtScopeError(
      'claimDelimiter and claimScopeDelimiter can not be the same character',
      'wrong_configuration',
      { claimDelimiter, claimScopeDelimiter }
    )
  }

  return {
    adminClaimEnabled,
    claimCharset,
    claimDelimiter,
    claimScopeDelimiter,
    scopeKey,
    scopeRequired,
    tokenKey
  }
}

/**
 * Returns a new array of processed arguments of factory function.
 *
 * @param {Array<function|string>} claims List of arguments passed to the middleware factory function.
 * @param {string} claimCharset Regexp string of allowed characters in permission name.
 * @param {string} claimScopeDelimiter Character that separates permission's name and scope.
 * @returns {Array<function|string[]>}
 */
function factoryArgv(claims, claimCharset, claimScopeDelimiter) {
  if (!claims.length) {
    throw new ExpressJwtScopeError(
      'No permissions were requested to check in the access token',
      'empty_argument_list'
    )
  }
  const hash = {}
  const outputArgs = []
  const requestedClaimRegex = new RegExp(
    `^${claimCharset}+(\\${claimScopeDelimiter}${claimCharset}+)*$`
  )
  for (const [index, claim] of claims.entries()) {
    if (isFunction(claim)) {
      outputArgs.push(claim)
    } else if (isString(claim)) {
      if (!requestedClaimRegex.test(claim)) {
        throw new ExpressJwtScopeError(
          'Requested permission has invalid format',
          'invalid_argument',
          {
            argPos: index + 1,
            argValue: claim,
            claimCharset,
            claimScopeDelimiter
          }
        )
      } else if (!(claim in hash)) {
        hash[claim] = true
        outputArgs.push(claim.split(claimScopeDelimiter))
      }
    } else {
      throw new ExpressJwtScopeError(
        'Requested permission must be a function or a string',
        'invalid_argument',
        { argPos: index + 1, argValue: claim }
      )
    }
  }

  return outputArgs
}

/**
 * Returns list of granted claims.
 *
 * @param {string|string[]} scope Scope value retrieved from the access token.
 * @param {string} claimDelimiter Character used to separate claims if scope is a string.
 * @param {string} claimCharset Regexp string of allowed characters in permission name.
 * @param {string} claimScopeDelimiter Character that separates permission's name and scope.
 * @returns {string[][]}
 */
function parseGrantedScope(
  scope,
  claimDelimiter,
  claimCharset,
  claimScopeDelimiter
) {
  const grantedClaimRegex = new RegExp(
    `^${claimCharset}+(\\${claimScopeDelimiter}(${claimCharset}+|\\*))*$`
  )

  let claimList = scope
  if (isString(scope)) {
    claimList = scope.split(claimDelimiter)
  } else if (!Array.isArray(scope)) {
    throw new InternalServerError(
      `Scope value must be an array or '${claimDelimiter}'-separated string`,
      'unsupported_scope_type',
      { scope, type: scope.constructor.name }
    )
  }

  const outputScope = []
  for (const [index, claim] of claimList.entries()) {
    if (!isString(claim) || !grantedClaimRegex.test(claim)) {
      if (isString(scope) && claimList.length === 1) {
        throw new InternalServerError(
          'Scope value contains unallowed characters or uses wrong character as delimiter',
          'unsupported_scope_value',
          {
            scope,
            claimDelimiter,
            claimCharset,
            claimScopeDelimiter
          }
        )
      } else {
        throw new InternalServerError(
          'Permission in the scope has unsupported format',
          'unsupported_permission_value',
          {
            scope,
            index,
            permission: claim,
            claimCharset,
            claimScopeDelimiter
          }
        )
      }
    } else {
      outputScope.push(claim.split(claimScopeDelimiter))
    }
  }

  return outputScope
}

module.exports = {
  deepCopy,
  factoryArgv,
  isFunction,
  isString,
  moduleArgv,
  parseGrantedScope
}
