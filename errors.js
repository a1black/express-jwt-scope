'use strict'

class ExpressJwtScopeError extends Error {
  constructor(message, code) {
    super(message)
    this.name = this.constructor.name
    this.code = code
  }
}

class ForbiddenError extends ExpressJwtScopeError {
  constructor(message = 'Forbidden', code = 'authorization_fail') {
    super(message, code)
    this.expose = true
    this.status = this.statusCode = 403
  }
}

class InternalServerError extends ExpressJwtScopeError {
  constructor(message, code) {
    super(message, code)
    this.expose = false
    this.status = this.statusCode = 500
  }
}

module.exports = {
  ExpressJwtScopeError,
  ForbiddenError,
  InternalServerError
}
