'use strict'

const path = require('path')
const get = require('lodash.get')
const utils = require('./utils')
const { InternalServerError, ForbiddenError } = require('./errors')

/**
 * @returns {function} Wrapper that deep-copies scope value before passing it to user defined function.
 */
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

/**
 * Rule assumes that both arrays (granted permissions and requested one) have consecutive indexes.
 *
 * @returns {function} Function that returns `true` if `requested` matches entry in the granted scope.
 */
const inGrantedRule = requested => grantedScope =>
  grantedScope.some(
    granted =>
      granted.length === requested.length &&
      granted.every(
        (scope, index) => scope === '*' || scope === requested[index]
      )
  )

/**
 * @returns {function} Wrapper that negates result of `rule`.
 */
const notRule = rule => async (grantedScope, helpers) =>
  !(await rule(grantedScope, helpers))

/**
 * @returns {function} Function that returns `true` if all function in `rules` returns `true`.
 */
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

/**
 * @returns {function} Function that returns `true` if any function in `rules` returns `true`.
 */
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

/**
 * Returns middleware factory function.
 *
 * @param {object} options Configuration options of factory function.
 * @param {string} [options.tokenKey=user] Path to token in the request, see {@link https://lodash.com/docs#get|lodash.get()}.
 * @param {string} [options.scopeKey=scope] Path to scope field inside the token, see {@link https://lodash.com/docs#get|lodash.get()}.
 * @param {boolean} [options.scopeRequired=true] Determines what error would be raise if scope field is `undefined`.
 * @param {boolean} [options.adminClaimEnabled=false] If `true` check for *admin* claim in the access token first.
 * @param {string} [options.claimDelimiter=,] Single char that separates granted claims in the access token.
 * @param {string} [options.claimScopeDelimiter=:] Single char that separates claim and its scope.
 */
function expressJwtScopeModule(options) {
  const {
    adminClaimEnabled,
    claimCharset,
    claimDelimiter,
    claimScopeDelimiter,
    scopeKey,
    scopeRequired,
    tokenKey
  } = utils.moduleArgv(options)

  /** Returns 403 HTTP status error. */
  const error403 = (message = 'Forbidden', code = 'authorization_fail') =>
    new ForbiddenError(message, code)

  const ruleQueueBuilder = claims => {
    const queue = utils
      .factoryArgv(claims, claimCharset, claimScopeDelimiter)
      .map(claim =>
        utils.isFunction(claim) ? userRule(claim) : inGrantedRule(claim)
      )
    return queue.length === 1 ? queue[0] : andReducer(...queue)
  }

  /** Returns granted scope from the access token or throwns status 500 error. */
  const fetchGrantedScope = req => {
    try {
      const isEmpty = value =>
        value === undefined ||
        value === '' ||
        (Array.isArray(value) && !value.length)

      // Get JWT payload
      const token = get(req, tokenKey, undefined)
      if (!token) {
        throw new InternalServerError(
          'Access token not found in the request object',
          'token_not_found',
          { tokenKey }
        )
      }
      // Get scope value
      const scope = get(token, scopeKey, undefined) || []
      if (isEmpty(scope) && scopeRequired) {
        throw error403(undefined, 'no_permissions')
      }

      const grantedScope = utils.parseGrantedScope(
        scope,
        claimDelimiter,
        claimCharset,
        claimScopeDelimiter
      )

      return [token, scope, grantedScope]
    } catch (err) {
      if (InternalServerError.isError(err)) {
        Object.assign(err.details, {
          method: req.method,
          url: req.originUrl.split('?', 1)[0],
          route: path.posix.join(req.baseUrl, req.route.path)
        })
      }

      throw err
    }
  }

  // Middleware factory function
  return (...requested) => {
    let accessChecker = ruleQueueBuilder(requested)

    if (adminClaimEnabled) {
      accessChecker = orReducer(inGrantedRule(['admin']), accessChecker)
    }

    const middleware = async (req, res, next) => {
      const [token, scope, grantedScope] = fetchGrantedScope(req)

      const helpers = {
        error(message, code) {
          throw error403(message, code)
        },
        request: req,
        scope,
        token,
        scopeKey,
        tokenKey,
        claimDelimiter,
        claimScopeDelimiter
      }

      if (await accessChecker(grantedScope, helpers)) {
        next()
      } else {
        throw error403()
      }
    }

    /**
     * Wraps previously provided rules in a disjunction with `requested`.
     *
     * @example
     * expressJwtScopeModule()('rule1', 'rule2').or('rule3', 'rule4')
     * // => ('rule1' && 'rule2') || ('rule3' && 'rule4')
     */
    middleware.or = (...requested) => {
      accessChecker = orReducer(accessChecker, ruleQueueBuilder(requested))
      return middleware
    }

    /**
     * Wraps previously provided rules in a conjunction with negation of `requested`.
     *
     * @example
     * expressJwtScopeModule()('rule1', 'rule2').not('rule3')
     * // => ('rule1' && 'rule2') && !('rule3')
     */
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
}

module.exports = expressJwtScopeModule
