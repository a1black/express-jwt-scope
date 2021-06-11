'use strict'

const path = require('path')

/**
 * Module specific error.
 *
 * @property {string} message Human-friendly description of occured error.
 * @property {string} code Alphanumeric string identifying error type.
 * @property {object} details Additional information describing error.
 */
class ExpressJwtScopeError extends Error {
  /**
   * @param {string} message String describing error.
   * @param {string} code Short code identifying error type.
   * @param {object} kwargs Additional properties that will be assigned to error instance.
   */
  constructor(message, code, kwargs) {
    super(message)
    this.name = this.constructor.name
    this.code = code
    this.details = Object.assign({}, kwargs)
  }

  static isError(err) {
    return err instanceof this
  }
}

/**
 * Thrown then token's payload or scope are undefined.
 *
 * @property {string} message Human-friendly description of occured error.
 * @property {string} code Alphanumeric string identifying error type.
 * @property {boolean} [expose=false] Whether error message should be sent to the client.
 * @property {number} [status=500] HTTP status code.
 * @property {object} details Information that helps to identify end-point where this error occured.
 * @property {string} details.url Path part of request URL.
 * @property {string} details.method The HTTP method of the request.
 */
class InternalServerError extends ExpressJwtScopeError {
  constructor(message, code, kwargs) {
    super(message, code, kwargs)
    this.expose = false
    this.status = this.statusCode = 500
  }
}

/**
 * Thrown then access token haven't got requested permissions.
 */
class ForbiddenError extends ExpressJwtScopeError {
  constructor(message, code) {
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
