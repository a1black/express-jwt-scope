'use strict'

const get = require('lodash.get')
const utils = require('./utils')
const { InternalServerError, ForbiddenError } = require('./errors')

/** Checks that access token has admin claim and it's set to `true`. */
const adminRule = path => (_, helpers) => {
  const adminClaim = get(helpers.token, path, undefined)
  helpers.isAdmin = adminClaim === true || adminClaim === 1
  return helpers.isAdmin
}

/** Custom admin claim checker. */
const userAdminRule = callable => async (grantedScope, helpers) => {
  const result = await callable(
    utils.deepCopy(grantedScope),
    Object.assign({}, helpers, {
      originScope: utils.deepCopy(helpers.originScope),
      token: utils.deepCopy(helpers.token)
    })
  )
  helpers.isAdmin = result
  return result
}

/** Invokes `callable` with copies of recieved arguments. */
const userRule = callable => async (grantedScope, helpers) =>
  callable(
    utils.deepCopy(grantedScope),
    Object.assign({}, helpers, {
      originScope: utils.deepCopy(helpers.originScope),
      token: utils.deepCopy(helpers.token)
    })
  )

/** Checks `grantedScope` for `requested` permission. */
const inGrantedRule = requested => grantedScope =>
  grantedScope.some(granted => {
    if (granted.length === requested.length) {
      return granted.every(
        (scope, index) => scope === '*' || scope === requested[index]
      )
    } else if (granted.length > requested.length) {
      const tail = granted.slice(requested.length)
      return (
        tail.every(scope => scope === '*') &&
        requested.every((scope, index) => scope === granted[index])
      )
    } else {
      return false
    }
  })

/** Negates return of `rule` function. */
const notRule = rule => async (grantedScope, helpers) =>
  !(await rule(grantedScope, helpers))

/** Reduces `rules` return values using `&&` operator. */
const andReducer =
  (...rules) =>
  async (grantedScope, helpers) => {
    for (const rule of rules) {
      if (!(await rule(grantedScope, helpers))) {
        return false
      }
    }

    return true
  }

/** Reduces `rules` return values using `||` operator. */
const orReducer =
  (...rules) =>
  async (grantedScope, helpers) => {
    for (const rule of rules) {
      if (await rule(grantedScope, helpers)) {
        return true
      }
    }

    return false
  }

function expressJwtScope(options) {
  const {
    adminKey,
    claimCharset,
    claimDelimiter,
    claimScopeDelimiter,
    scopeKey,
    tokenKey
  } = utils.moduleArgv(options)

  /** Creates checker function from list of requested permissions. */
  const ruleQueueBuilder = claims => {
    const queue = utils
      .factoryArgv(claims, claimCharset, claimScopeDelimiter)
      .map(claim =>
        utils.isFunction(claim) ? userRule(claim) : inGrantedRule(claim)
      )
    return queue.length === 1 ? queue[0] : andReducer(...queue)
  }

  /** Factory function. */
  const middlewareFactory = (...permissions) => {
    let accessChecker

    if (adminKey) {
      accessChecker = utils.isFunction(adminKey)
        ? userAdminRule(adminKey)
        : adminRule(adminKey)
      if (permissions.length) {
        accessChecker = orReducer(accessChecker, ruleQueueBuilder(permissions))
      }
    } else {
      accessChecker = ruleQueueBuilder(permissions)
    }

    /** Request handler. */
    const middleware = async (req, res, next) => {
      const token = get(req, tokenKey, undefined)
      if (!token) {
        throw new InternalServerError(
          `Access token not found at '${tokenKey}'`,
          'token_not_found'
        )
      }

      const scope = get(token, scopeKey, undefined)
      const grantedScope = utils.parseGrantedScope(
        scope,
        claimDelimiter,
        claimCharset,
        claimScopeDelimiter
      )

      const helpers = {
        error(message) {
          throw new ForbiddenError(message)
        },
        req,
        claimDelimiter,
        claimScopeDelimiter,
        isAdmin: undefined,
        originScope: scope,
        token
      }

      if (await accessChecker(grantedScope, helpers)) {
        next()
      } else {
        throw new ForbiddenError()
      }
    }

    middleware.or = (...permissions) => {
      accessChecker = orReducer(accessChecker, ruleQueueBuilder(permissions))
      return middleware
    }

    middleware.not = (...permissions) => {
      accessChecker = andReducer(
        accessChecker,
        notRule(ruleQueueBuilder(permissions))
      )
      return middleware
    }

    middleware.promisify = () => (req, res, next) =>
      Promise.resolve()
        .then(() => middleware(req, res, next))
        .catch(next)

    return middleware
  }

  return middlewareFactory
}

module.exports = expressJwtScope
