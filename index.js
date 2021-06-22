'use strict'

const get = require('lodash.get')
const utils = require('./utils')
const { InternalServerError, ForbiddenError } = require('./errors')

/** Checks that access token has admin claim and it's set to `true`. */
const adminRule =
  path =>
  (_, { token }) =>
    [true, 1].includes(get(token, path, undefined))

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
  grantedScope.some(
    granted =>
      granted.length === requested.length &&
      granted.every(
        (scope, index) => scope === '*' || scope === requested[index]
      )
  )

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
  const middlewareFactory = (...requestedPermissions) => {
    let accessChecker

    if (adminKey) {
      accessChecker = utils.isFunction(adminKey)
        ? userRule(adminKey)
        : adminRule(adminKey)
      if (requestedPermissions.length) {
        accessChecker = orReducer(
          accessChecker,
          ruleQueueBuilder(requestedPermissions)
        )
      }
    } else {
      accessChecker = ruleQueueBuilder(requestedPermissions)
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
        originScope: scope,
        token
      }

      if (await accessChecker(grantedScope, helpers)) {
        next()
      } else {
        throw new ForbiddenError()
      }
    }

    middleware.or = (...requestedPermissions) => {
      accessChecker = orReducer(
        accessChecker,
        ruleQueueBuilder(requestedPermissions)
      )
      return middleware
    }

    middleware.not = (...requestedPermissions) => {
      accessChecker = andReducer(
        accessChecker,
        notRule(ruleQueueBuilder(requestedPermissions))
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
