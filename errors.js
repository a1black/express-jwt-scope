'use strict'

/**
 * Module specific error.
 *
 * @property {string} message Human-friendly description of occured error.
 * @property {string} code Alphanumeric string identifying error type.
 */
class ExpressJwtScopeError extends Error {
  /**
   * @param {string} message String describing error.
   * @param {string} code Short code identifying error type.
   */
  constructor(message, code) {
    super(message)
    this.name = this.constructor.name
    this.code = code
  }
}

/**
 * Thrown then token's payload or scope are undefined.
 *
 * @property {boolean} [expose=false] Whether error message should be sent to the client.
 * @property {number} [status=500] HTTP status code.
 */
class InternalServerError extends ExpressJwtScopeError {
  constructor(message, code) {
    super(message, code)
    this.expose = false
    this.status = this.statusCode = 500
  }
}

/**
 * Thrown then access token haven't got requested permissions.
 */
class ForbiddenError extends ExpressJwtScopeError {
  constructor(message = 'Forbidden', code = 'authorization_fail') {
    super(message, code)
    this.expose = true
    this.status = this.statusCode = 403
  }
}

module.exports = {
  ExpressJwtScopeError,
  InternalServerError,
  ForbiddenError
}
