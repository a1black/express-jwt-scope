'use strict'

const get = require('lodash.get')
const utils = require('./utils')
const { InternalServerError, ForbiddenError } = require('./errors')

/**
 * @typedef CheckHelperObject
 * @property {function} error Function that throws 403:Forbidden error.
 * @property {Object} req Client request object.
 * @property {string|string[]} scope Origin value of granted permissions.
 * @property {Object} token The access token.
 */
/**
 * @callback CheckCallback
 * @param {string[][]} grantedScope
 * @param {CheckHelperObject} [helpers]
 * @returns {boolean}
 */
/**
 * @typedef {(string|CheckCallback)} RequestedPermission
 */

/**
 * Returns wrapper function that invokes `callable` with copies of supplied arguments.
 *
 * @private
 * @param {CheckCallback} callable Callable object to wrap.
 * @returns {CheckCallback}
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
 * Returns function that check for `requested` permission in the granted permissions.
 *
 * This function assumes that granted permissions and requested one have consecutive indexes.
 *
 * @private
 * @param {string[]} requested Permission to match in the granted permissions.
 * @returns {CheckCallback}
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
 * Returns wrapper function that negates return of `rule`.
 *
 * @private
 * @param {CheckCallback} rule Callable object to wrap.
 * @returns {CheckCallback}
 */
const notRule = rule => async (grantedScope, helpers) =>
  !(await rule(grantedScope, helpers))

/**
 * Returns function that invokes callables from `rules` and produces conjunction of thiers returns.
 *
 * Produced function returns on first `false` operand.
 *
 * @private
 * @param {...CheckCallback} rules List of callable objects.
 * @returns {CheckCallback}
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
 * Returns function that invokes callables from `rules` and produces disjunction of thiers returns.
 *
 * Produced function returns on first `true` operand.
 *
 * @private
 * @param {...CheckCallback} rules List of callable objects.
 * @returns {CheckCallback}
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
 * @typedef ConfigurationParameter
 * @property {boolean} [adminClaimEnabled=false] If `true` check for *admin* claim in the access token first.
 * @property {string} [claimDelimiter=,] Single char that separates granted claims in the access token.
 * @property {string} [claimScopeDelimiter=:] Single char that separates claim and its scope.
 * @property {string|string[]} [scopeKey=scope] Path to scope field inside the token, see {@link https://lodash.com/docs#get|lodash.get()}.
 * @property {boolean} [scopeRequired=true] Determines what error would be raise if scope field is `undefined`.
 * @property {string|string[]} [tokenKey=user] Path to token in the request, see {@link https://lodash.com/docs#get|lodash.get()}.
 */
/**
 * Returns middleware factory function.
 *
 * @exports express-jwt-scope
 * @param {ConfigurationParameter} options Configuration for module executables.
 * @returns {middlewareFactory}
 * @throws {ExpressJwtScopeError} Thrown if invalid configuration option was supplied.
 */
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

  /**
   * Wraps requested permissions with `andReducer`.
   *
   * @private
   */
  const ruleQueueBuilder = claims => {
    const queue = utils
      .factoryArgv(claims, claimCharset, claimScopeDelimiter)
      .map(claim =>
        utils.isFunction(claim) ? userRule(claim) : inGrantedRule(claim)
      )
    return queue.length === 1 ? queue[0] : andReducer(...queue)
  }

  /**
   * Produces middleware that check for `requested` permissions in the access token.
   *
   * @global
   * @param {...RequestedPermission} requested Set of permissions needed to pass authorization check.
   * @returns {middleware} Express middleware function.
   * @throws {ExpressJwtScopeError} Thrown if invalid argument supplied.
   */
  const middlewareFactory = (...requested) => {
    let accessChecker = ruleQueueBuilder(requested)

    if (adminClaimEnabled) {
      accessChecker = orReducer(inGrantedRule(['admin']), accessChecker)
    }

    /**
     * Express middleware function.
     *
     * @global
     * @namespace
     * @param {Object} req Client request object.
     * @param {Object} res Server response object.
     * @param {function} next Function that invokes next middleware.
     * @returns {Promise}
     * @throws {ForbiddenError} If requested permissions weren't meet.
     */
    const middleware = async (req, res, next) => {
      // Get JWT payload
      const token = get(req, tokenKey, undefined)
      if (!token) {
        throw new InternalServerError(
          `Access token not found at path: '${tokenKey}'`,
          'token_not_found'
        )
      }
      // Get scope value
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

    /**
     * Adds alternative set of permissions to check in the access token if other failed.
     *
     * @memberof middleware
     * @example
     * expressJwtScopeModule()('rule1', 'rule2').or('rule3', 'rule4')
     * // => ('rule1' && 'rule2') || ('rule3' && 'rule4')
     * @param {...RequestedPermission} requested Set of permissions to check.
     * @returns {middleware}
     */
    middleware.or = (...requested) => {
      accessChecker = orReducer(accessChecker, ruleQueueBuilder(requested))
      return middleware
    }

    /**
     * Extends initial set of required permissions with negation of `requested` permissions.
     *
     * @memberof middleware
     * @example
     * expressJwtScopeModule()('rule1', 'rule2').not('rule3')
     * // => ('rule1' && 'rule2') && !('rule3')
     * @param {...RequestedPermission} requested Set of permissions that mustn't be present in the access token.
     * @returns {middleware}
     */
    middleware.not = (...requested) => {
      accessChecker = andReducer(
        accessChecker,
        notRule(ruleQueueBuilder(requested))
      )
      return middleware
    }

    /**
     * Returns promise with rejection handler as follows `.catch(next)`.
     *
     * @memberof middleware
     * @returns {Promise}
     */
    middleware.promisify = () => (req, res, next) =>
      Promise.resolve()
        .then(() => middleware(req, res, next))
        .catch(next)

    return middleware
  }

  return middlewareFactory
}

module.exports = expressJwtScope
