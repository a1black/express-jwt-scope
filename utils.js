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

/**
 * Returns `true` if argument is a function.
 */
function isFunction(value) {
  return typeof value === 'function'
}

/**
 * Returns `true` if argument is a string.
 */
function isString(value) {
  return typeof value === 'string' || value instanceof String
}

/**
 * Configuration object used by module's entities.
 * @typedef ModuleConfig
 * @property {boolean} [adminClaimEnabled]
 * @property {string} [claimDelimiter]
 * @property {string} [claimScopeDelimiter]
 * @property {string|string[]} [scopeKey]
 * @property {boolean} [scopeRequired]
 * @property {string|string[]} [tokenKey]
 */
/**
 * Returns configuration object using values in `option` argument and module defaults.
 *
 * @param {ModuleConfig}
 * @throws {ExpressJwtScopeError} Thrown if invalid configuration option was supplied.
 */
function moduleArgv(options) {
  let {
    adminClaimEnabled,
    claimDelimiter,
    claimScopeDelimiter,
    scopeKey = 'scope',
    scopeRequired,
    tokenKey = 'user'
  } = options || {}
  const claimCharset = '[a-zA-Z0-9_]'
  const delimiterRegex = /[-!"#$%&'()+,./:;<=>?@[\]^`{|}~]/

  const validDelimiter = delimiter =>
    isString(delimiter) && delimiter.length === 1
  const validClaimDelimiter = delimiter =>
    validDelimiter(delimiter) &&
    (delimiterRegex.test(delimiter) || delimiter === ' ')
  const validClaimScopeDelimiter = delimiter =>
    validDelimiter(delimiter) && delimiterRegex.test(delimiter)

  if (claimDelimiter && !validClaimDelimiter(claimDelimiter)) {
    throw new ExpressJwtScopeError(
      'claimDelimiter must be unescaped ASCII punctuation character or space,' +
        ` got '${claimDelimiter}'`,
      'invalid_config_option'
    )
  } else if (
    claimScopeDelimiter &&
    !validClaimScopeDelimiter(claimScopeDelimiter)
  ) {
    throw new ExpressJwtScopeError(
      'claimScopeDelimiter must be unescaped ASCII punctuation character,' +
        ` got '${claimScopeDelimiter}'`,
      'invalid_config_option'
    )
  }

  adminClaimEnabled = adminClaimEnabled === true
  scopeRequired = scopeRequired !== false

  claimDelimiter = claimDelimiter || ','
  claimScopeDelimiter = claimScopeDelimiter || ':'
  if (claimDelimiter === claimScopeDelimiter) {
    throw new ExpressJwtScopeError(
      'claimDelimiter and claimScopeDelimiter can not be the same character',
      'invalid_configuration'
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
 * @throws {ExpressJwtScopeError} Thrown if recieved permsiion of invalid type or format.
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
          `Invalid permission was supplied at [${index + 1}]: '${claim}'`,
          'invalid_argument'
        )
      } else if (!(claim in hash)) {
        hash[claim] = true
        outputArgs.push(claim.split(claimScopeDelimiter))
      }
    } else {
      throw new ExpressJwtScopeError(
        'Requested permission must be a function or a string,' +
          ` got [${index + 1}]: ${claim}`,
        'invalid_argument'
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
 * @throws {InternalServerError} If granted permissions have unsupported format or type.
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
    claimList = scope ? scope.split(claimDelimiter) : []
  } else if (scope === undefined) {
    claimList = []
  } else if (!Array.isArray(scope)) {
    throw new InternalServerError(
      `Scope value must be an array or '${claimDelimiter}'-separated string,` +
        ` got ${scope}`,
      'unsupported_scope_type'
    )
  }

  const outputScope = []
  for (const [index, claim] of claimList.entries()) {
    if (!isString(claim) || !grantedClaimRegex.test(claim)) {
      throw new InternalServerError(
        `Unsupported granted permission at [${index}]: '${claim}'`,
        'unsupported_permission_value'
      )
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
