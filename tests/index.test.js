const expressJwtScope = require('../index')
const { InternalServerError, ForbiddenError } = require('../errors')
const { TestWatcher } = require('jest')

// URL and method for stub request object
const TEST_METHOD = 'GET'
const TEST_URL = '/unit/test'

const stubrequest = (tokenKey, scopeKey, scope) =>
  Object.assign(
    {},
    {
      baseUrl: '',
      method: TEST_METHOD,
      originUrl: TEST_URL,
      route: {
        path: TEST_URL
      }
    },
    { [tokenKey]: { [scopeKey]: scope } }
  )

test('access token not found, rejects InternalServerError', async () => {
  const tokenKey = 'user'
  const scopeKey = 'scope'
  const middleware = expressJwtScope({ tokenKey, scopeKey })('read')
  const req = stubrequest('differentKey', scopeKey, 'read')

  await expect(middleware(req)).rejects.toThrow(InternalServerError)
})

describe('granted scope is empty and scope is required, rejects ForbiddenError', () => {
  const tokenKey = 'user'
  const scopeKey = 'scope'
  const middleware = expressJwtScope({
    tokenKey,
    scopeKey,
    scopeRequired: true
  })('read')

  test.each([
    ['differentKey', 'read'],
    [scopeKey, undefined],
    [scopeKey, ''],
    [scopeKey, []]
  ])("%s: '%s'", async (scopeKey, scope) => {
    const req = stubrequest(tokenKey, scopeKey, scope)

    await expect(middleware(req)).rejects.toThrow(ForbiddenError)
  })
})

describe("logical 'and' for multiple requested permissions", () => {
  const tokenKey = 'user'
  const scopeKey = 'scope'
  const scope = 'read,write,user:*,post:delete'

  test('permission match, resolves true', async () => {
    const middleware = expressJwtScope({
      tokenKey,
      scopeKey
    })('write', 'user:add', 'post:delete')
    const req = stubrequest(tokenKey, scopeKey, scope)
    const next = jest.fn()

    await middleware(req, {}, next)
    expect(next).toHaveBeenCalled()
  })

  test('permission not match, throws ForbiddenError', async () => {
    const middleware = expressJwtScope({
      tokenKey,
      scopeKey,
      scopeRequired: true
    })('write', 'user:add', 'group:delete')
    const req = stubrequest(tokenKey, scopeKey, scope)

    await expect(middleware(req)).rejects.toThrow(ForbiddenError)
  })

  test('permission is a truthfull function, resolves true', async () => {
    const truthy1 = jest.fn().mockReturnValue(true)
    const truthy2 = jest.fn().mockResolvedValue(true)

    const req = stubrequest(tokenKey, scopeKey, scope)
    const next = jest.fn()

    const middleware = expressJwtScope({
      tokenKey,
      scopeKey
    })(truthy1, truthy2)

    await middleware(req, {}, next)
    expect(next).toHaveBeenCalled()
    expect(truthy1).toHaveBeenCalled()
    expect(truthy2).toHaveBeenCalled()
  })

  test('permission check until first failure, throws ForbiddenError', async () => {
    const falsy = jest.fn().mockResolvedValue(false)
    const truthy = jest.fn().mockReturnValue(true)

    const req = stubrequest(tokenKey, scopeKey, scope)

    const middleware = expressJwtScope({
      tokenKey,
      scopeKey
    })(falsy, truthy)

    await expect(middleware(req)).rejects.toThrow(ForbiddenError)
    expect(falsy).toHaveBeenCalled()
    expect(truthy).not.toHaveBeenCalled()
  })

  describe.each([undefined, '', []])(
    'granted scope is empty and optional, expect execution of functional claims',
    scope => {
      test(`scope: '${scope}'`, async () => {
        const truthy1 = jest.fn().mockReturnValue(true)
        const truthy2 = jest.fn().mockResolvedValue(true)

        const req = stubrequest(tokenKey, scopeKey, scope)
        const next = jest.fn()

        const middleware = expressJwtScope({
          tokenKey,
          scopeKey,
          scopeRequired: false
        })(truthy1, truthy2)

        await middleware(req, {}, next)
        expect(next).toHaveBeenCalled()
        expect(truthy1).toHaveBeenCalled()
        expect(truthy2).toHaveBeenCalled()
      })
    }
  )
})

describe("logical 'or' for multiple requested permissions", () => {
  const tokenKey = 'user'
  const scopeKey = 'scope'
  const scope = 'read,write,user:*,post:delete'

  test('at least one truthfull claim, resolves true', async () => {
    const truthy1 = jest.fn().mockReturnValue(true)
    const truthy2 = jest.fn().mockResolvedValue(true)

    const middleware = expressJwtScope({
      tokenKey,
      scopeKey
    })('delete').or(truthy1, truthy2)

    const req = stubrequest(tokenKey, scopeKey, scope)
    const next = jest.fn()

    await middleware(req, {}, next)
    expect(next).toHaveBeenCalled()
    expect(truthy1).toHaveBeenCalled()
    expect(truthy2).toHaveBeenCalled()
  })

  test('check until first success, resolves true', async () => {
    const truthy1 = jest.fn().mockReturnValue(true)
    const truthy2 = jest.fn().mockReturnValue(true)
    const falsy = jest.fn().mockReturnValue(false)

    const middleware = expressJwtScope({
      tokenKey,
      scopeKey
    })(falsy)
      .or(truthy1)
      .or(truthy2)

    const req = stubrequest(tokenKey, scopeKey, scope)
    const next = jest.fn()

    await middleware(req, {}, next)
    expect(next).toHaveBeenCalled()
    expect(falsy).toHaveBeenCalled()
    expect(truthy1).toHaveBeenCalled()
    expect(truthy2).not.toHaveBeenCalled()
  })
})

test('negate falsy rule, resolves true', async () => {
  const tokenKey = 'user'
  const scopeKey = 'scope'
  const scope = 'read,write,user:*,post:delete'

  const truthy = jest.fn().mockReturnValue(true)
  const falsy = jest.fn().mockReturnValue(false)

  const middleware = expressJwtScope({
    tokenKey,
    scopeKey
  })(truthy).not(falsy)

  const req = stubrequest(tokenKey, scopeKey, scope)
  const next = jest.fn()

  await middleware(req, {}, next)
  expect(next).toHaveBeenCalled()
  expect(truthy).toHaveBeenCalled()
  expect(falsy).toHaveBeenCalled()
})
