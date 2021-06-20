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
