const expressJwtScope = require('../index')
const { InternalServerError, ForbiddenError } = require('../errors')

const ADMIN_KEY = 'admin'
const SCOPE_KEY = 'scope'
const TOKEN_KEY = 'user'

const makeMiddleware = options =>
  expressJwtScope(
    Object.assign(
      {
        scopeKey: SCOPE_KEY,
        tokenKey: TOKEN_KEY
      },
      options || {}
    )
  )

const stubrequest = (scope, admin) => ({
  [TOKEN_KEY]: {
    [ADMIN_KEY]: admin,
    [SCOPE_KEY]: scope
  }
})

test('access token not found, rejects InternalServerError', async () => {
  const middleware = makeMiddleware()('read')
  await expect(middleware({})).rejects.toThrow(InternalServerError)
})

describe('granted scope is empty or undefined, rejects ForbiddenError', () => {
  test.each([undefined, '', []])('%s', async scope => {
    const middleware = makeMiddleware()('read')
    const req = stubrequest(scope)
    await expect(middleware(req)).rejects.toThrow(ForbiddenError)
  })
})

describe('check with admin rule enabled', () => {
  test('admin claim is false, rejects ForbiddenError', async () => {
    const middleware = makeMiddleware({ adminKey: ADMIN_KEY })()
    const req = stubrequest(undefined, undefined)
    await expect(middleware(req)).rejects.toThrow(ForbiddenError)
  })

  test('admin claim is false with fallback permissions, resolves true', async () => {
    const middleware = makeMiddleware({ adminKey: ADMIN_KEY })(
      'write',
      'delete'
    )
    const req = stubrequest('read,write,delete', undefined)
    const next = jest.fn()
    await middleware(req, {}, next)
    expect(next).toHaveBeenCalledWith()
  })

  describe('admin claim truthfull values, resolves true', () => {
    test.each([true, 1])('%s', async admin => {
      const middleware = makeMiddleware({ adminKey: ADMIN_KEY })()
      const req = stubrequest(undefined, admin)
      const next = jest.fn()
      await middleware(req, {}, next)
      expect(next).toHaveBeenCalledWith()
    })
  })

  test('admin claim is callable, resolves true', async () => {
    const truthy = jest.fn().mockResolvedValue(true)
    const middleware = makeMiddleware({ adminKey: truthy })()
    const req = stubrequest(undefined, false)
    const next = jest.fn()
    await middleware(req, {}, next)
    expect(next).toHaveBeenCalledWith()
    expect(truthy).toHaveBeenCalled()
  })
})

describe("check set of permissions using logical 'and'", () => {
  test('expect success, resolves true', async () => {
    const truthy1 = jest.fn().mockReturnValue(true)
    const truthy2 = jest.fn().mockReturnValue(true)
    const middleware = makeMiddleware()(
      'post:write',
      'comment:add',
      truthy1,
      truthy2
    )
    const req = stubrequest('post:write,post:delete,comment:*')
    const next = jest.fn()
    await middleware(req, {}, next)
    expect(next).toHaveBeenCalledWith()
    expect(truthy1).toHaveBeenCalled()
    expect(truthy2).toHaveBeenCalled()
  })

  test('permission check until first failure, throws ForbiddenError', async () => {
    const truthy = jest.fn().mockReturnValue(true)
    const middleware = makeMiddleware()('write', truthy)
    const req = stubrequest('read')
    await expect(middleware(req)).rejects.toThrow(ForbiddenError)
    expect(truthy).not.toHaveBeenCalled()
  })
})

describe("check set of permission using logical 'or'", () => {
  test('permission check until first success, resolves true', async () => {
    const falsy = jest.fn().mockReturnValue(false)
    const truthy1 = jest.fn().mockReturnValue(true)
    const truthy2 = jest.fn().mockReturnValue(true)
    const middleware = makeMiddleware()('write')
      .or(falsy)
      .or(truthy1)
      .or(truthy2)
    const req = stubrequest('read')
    const next = jest.fn()
    await middleware(req, {}, next)
    expect(next).toHaveBeenCalledWith()
    expect(falsy).toHaveBeenCalled()
    expect(truthy1).toHaveBeenCalled()
    expect(truthy2).not.toHaveBeenCalled()
  })
})

describe("check set of permissions using logical 'not'", () => {
  test('expect success, resolves true', async () => {
    const falsy = jest.fn().mockResolvedValue(false)
    const middleware = makeMiddleware()('read').not(falsy)
    const req = stubrequest('read')
    const next = jest.fn()
    await middleware(req, {}, next)
    expect(next).toHaveBeenCalledWith()
    expect(falsy).toHaveBeenCalled()
  })

  test('expect failure, rejects ForbiddenError', async () => {
    const middleware = makeMiddleware()('write').not('delete')
    const req = stubrequest('read,write,delete')
    await expect(middleware(req)).rejects.toThrow(ForbiddenError)
  })
})
