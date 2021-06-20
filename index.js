'use strict'

const get = require('lodash.get')
const utils = require('./utils')
const { InternalServerError, ForbiddenError } = require('./errors')

/** Invokes `callable` with copies of recieved arguments. */
const userRule = callable => async (grantedScope, helpers) =>
  callable(
    utils.deepCopy(grantedScope),
    Object.assign({}, helpers, {
      scope: utils.deepCopy(helpers.scope),
      token: utils.deepCopy(helpers.token),
      scopeKey: utils.deepCopy(helpers.scopeKey),
      tokenKey: utils.deepCopy(helpers.tokenKey)
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
    adminClaimEnabled,
    claimCharset,
    claimDelimiter,
    claimScopeDelimiter,
    scopeKey,
    scopeRequired,
    tokenKey
  } = utils.moduleArgv(options)

  const ruleQueueBuilder = claims => {
    const queue = utils
      .factoryArgv(claims, claimCharset, claimScopeDelimiter)
      .map(claim =>
        utils.isFunction(claim) ? userRule(claim) : inGrantedRule(claim)
      )
    return queue.length === 1 ? queue[0] : andReducer(...queue)
  }

  const middlewareFactory = (...requested) => {
    let accessChecker = ruleQueueBuilder(requested)

    if (adminClaimEnabled) {
      accessChecker = orReducer(inGrantedRule(['admin']), accessChecker)
    }

    const middleware = async (req, res, next) => {
      const token = get(req, tokenKey, undefined)
      if (!token) {
        throw new InternalServerError(
          `Access token not found at path: '${tokenKey}'`,
          'token_not_found'
        )
      }

      const scope = get(token, scopeKey, undefined) || []
      const grantedScope = utils.parseGrantedScope(
        scope,
        claimDelimiter,
        claimCharset,
        claimScopeDelimiter
      )
      if (!grantedScope.length && scopeRequired) {
        throw new ForbiddenError()
      }

      const helpers = {
        error(message) {
          throw new ForbiddenError(message)
        },
        req,
        scope,
        token
      }

      if (await accessChecker(grantedScope, helpers)) {
        next()
      } else {
        throw new ForbiddenError()
      }
    }

    middleware.or = (...requested) => {
      accessChecker = orReducer(accessChecker, ruleQueueBuilder(requested))
      return middleware
    }

    middleware.not = (...requested) => {
      accessChecker = andReducer(
        accessChecker,
        notRule(ruleQueueBuilder(requested))
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
