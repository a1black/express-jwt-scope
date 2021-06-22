'use strict'

const { ExpressJwtScopeError, InternalServerError } = require('./errors')

function deepCopy(origin) {
  return typeof origin === 'object'
    ? JSON.parse(JSON.stringify(origin))
    : origin
}

function isFunction(value) {
  return typeof value === 'function'
}

function isString(value) {
  return typeof value === 'string' || value instanceof String
}

/** Returns module's configuration object. */
function moduleArgv(options) {
  let {
    adminKey,
    claimDelimiter = ',',
    claimScopeDelimiter = ':',
    scopeKey = 'scope',
    tokenKey = 'user'
  } = options || {}
  const claimCharset = '[a-zA-Z0-9_]'
  const delimiterRegex = /[-!"#$%&'()+,./:;<=>?@[\]^`{|}~]/

  const validDelimiter = delimiter =>
    isString(delimiter) &&
    delimiter.length === 1 &&
    delimiterRegex.test(delimiter)
  const validClaimDelimiter = delimiter =>
    validDelimiter(delimiter) || delimiter === ' '
  const validPropPath = path =>
    (isString(path) || Array.isArray(path)) && path.length

  if (!validPropPath(scopeKey)) {
    throw new ExpressJwtScopeError(
      `scopeKey expected non-empty string or an array, got '${scopeKey}'`,
      'invalid_config_option'
    )
  } else if (!validPropPath(tokenKey)) {
    throw new ExpressJwtScopeError(
      `tokenKey expected non-empty string or an array, got '${tokenKey}'`,
      'invalid_config_option'
    )
  } else if (
    !(adminKey === undefined || isFunction(adminKey) || validPropPath(adminKey))
  ) {
    throw new ExpressJwtScopeError(
      `adminKey expected non-empty string or an array, got '${adminKey}'`,
      'invalid_config_option'
    )
  } else if (!validClaimDelimiter(claimDelimiter)) {
    throw new ExpressJwtScopeError(
      'claimDelimiter expected unescaped ASCII punctuation character or space,' +
        ` got '${claimDelimiter}'`,
      'invalid_config_option'
    )
  } else if (!validDelimiter(claimScopeDelimiter)) {
    throw new ExpressJwtScopeError(
      'claimScopeDelimiter expected unescaped ASCII punctuation character,' +
        ` got '${claimScopeDelimiter}'`,
      'invalid_config_option'
    )
  } else if (claimDelimiter === claimScopeDelimiter) {
    throw new ExpressJwtScopeError(
      'claimDelimiter and claimScopeDelimiter can not be the same character',
      'invalid_config_option'
    )
  }

  adminKey = Array.isArray(adminKey) ? adminKey.join('.') : adminKey
  scopeKey = Array.isArray(scopeKey) ? scopeKey.join('.') : scopeKey
  tokenKey = Array.isArray(tokenKey) ? tokenKey.join('.') : tokenKey

  return {
    adminKey,
    claimCharset,
    claimDelimiter,
    claimScopeDelimiter,
    scopeKey,
    tokenKey
  }
}

/** Validate and parse arguments passed to the middleware factory function. */
function factoryArgv(claims, claimCharset, claimScopeDelimiter) {
  if (!claims.length) {
    throw new ExpressJwtScopeError(
      'Expected at least one argument',
      'empty_argument_list'
    )
  }
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
          `Invalid argument [${index + 1}]: '${claim}'`,
          'invalid_permission_value'
        )
      } else {
        outputArgs.push(claim.split(claimScopeDelimiter))
      }
    } else {
      throw new ExpressJwtScopeError(
        `String or function argument expected, got [${index + 1}]: ${claim}`,
        'invalid_argument_type'
      )
    }
  }

  return outputArgs
}

/** Validate and parse permissions obtained from the access token. */
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
      `Granted scope expected an array or '${claimDelimiter}'-separated string,` +
        ` got ${scope}`,
      'invalid_scope_type'
    )
  }

  const outputScope = []
  for (const [index, claim] of claimList.entries()) {
    if (!isString(claim) || !grantedClaimRegex.test(claim)) {
      throw new InternalServerError(
        `Invalid granted permission [${index}]: '${claim}'`,
        'invalid_permission_value'
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
