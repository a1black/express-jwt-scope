'use strict'

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
    credentialsRequired = true,
    requestProperty = 'permissions',
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

  if (!validPropPath(requestProperty)) {
    throw new TypeError(
      `requestProperty expected non-empty string or an array, got '${scopeKey}'`
    )
  } else if (!validPropPath(scopeKey)) {
    throw new TypeError(
      `scopeKey expected non-empty string or an array, got '${scopeKey}'`
    )
  } else if (!validPropPath(tokenKey)) {
    throw new TypeError(
      `tokenKey expected non-empty string or an array, got '${tokenKey}'`
    )
  } else if (
    !(adminKey === undefined || isFunction(adminKey) || validPropPath(adminKey))
  ) {
    throw new TypeError(
      `adminKey expected non-empty string or an array, got '${adminKey}'`
    )
  } else if (!validClaimDelimiter(claimDelimiter)) {
    throw new Error(
      'claimDelimiter expected unescaped ASCII punctuation character or space,' +
        ` got '${claimDelimiter}'`
    )
  } else if (!validDelimiter(claimScopeDelimiter)) {
    throw new Error(
      'claimScopeDelimiter expected unescaped ASCII punctuation character,' +
        ` got '${claimScopeDelimiter}'`
    )
  } else if (claimDelimiter === claimScopeDelimiter) {
    throw new Error(
      'claimDelimiter and claimScopeDelimiter can not be the same character'
    )
  }

  adminKey = Array.isArray(adminKey) ? adminKey.join('.') : adminKey
  requestProperty = Array.isArray(requestProperty)
    ? requestProperty.join('.')
    : requestProperty
  scopeKey = Array.isArray(scopeKey) ? scopeKey.join('.') : scopeKey
  tokenKey = Array.isArray(tokenKey) ? tokenKey.join('.') : tokenKey

  return {
    adminKey,
    claimCharset,
    claimDelimiter,
    claimScopeDelimiter,
    credentialsRequired: credentialsRequired !== false,
    requestProperty,
    scopeKey,
    tokenKey
  }
}

/** Validate and parse arguments passed to the middleware factory function. */
function factoryArgv(claims, claimCharset, claimScopeDelimiter) {
  if (!claims.length) {
    throw new Error('Expected at least one argument')
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
        throw new Error(`Invalid argument [${index + 1}]: '${claim}'`)
      } else {
        outputArgs.push(claim.split(claimScopeDelimiter))
      }
    } else {
      throw new TypeError(
        `String or function argument expected, got [${index + 1}]: ${claim}`
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
    return null
  }

  const outputScope = []
  for (const claim of claimList) {
    if (!isString(claim) || !grantedClaimRegex.test(claim)) {
      return null
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
