const { factoryArgv, moduleArgv, parseGrantedScope } = require('../utils')
const { ExpressJwtScopeError, InternalServerError } = require('../errors')

describe('moduleArgv helper function', () => {
  test.each([
    ['invalid delimiter character', { claimDelimiter: '_' }],
    ['too long delimiter string', { claimDelimiter: '::' }],
    [
      'duplicating delimiters',
      { claimDelimiter: ',', claimScopeDelimiter: ',' }
    ]
  ])('%s, throws ExpressJwtScopeError', (_, options) => {
    expect(() => moduleArgv(options)).toThrow(ExpressJwtScopeError)
  })

  test('configuration defaults, returns object', () => {
    expect(moduleArgv()).toMatchObject({
      adminClaimEnabled: false,
      claimDelimiter: ',',
      claimScopeDelimiter: ':',
      scopeKey: 'scope',
      scopeRequired: true,
      tokenKey: 'user'
    })
  })
})

describe('factoryArgv helper function', () => {
  test('Empty argument list, throws ExpressJwtScopeError', () => {
    expect(() => factoryArgv([])).toThrow(ExpressJwtScopeError)
  })

  test('Invalid argument type, throws ExpressJwtScopeError', () => {
    expect(() => factoryArgv([null])).toThrow(ExpressJwtScopeError)
    expect(() => factoryArgv([true])).toThrow(ExpressJwtScopeError)
    expect(() => factoryArgv([1000])).toThrow(ExpressJwtScopeError)
    expect(() => factoryArgv([['read', 'write']])).toThrow(ExpressJwtScopeError)
    expect(() => factoryArgv([{ read: true }])).toThrow(ExpressJwtScopeError)
  })

  describe("Unsupported characters in argument's value, throws ExpressJwtScopeError", () => {
    test.each(['user-posts:delete', 'user:add,user:drop', 'user:*', 'чтение'])(
      '%s',
      value => {
        const regex = '[a-z]'
        const delimiter = ':'
        expect(() => factoryArgv([value], regex, delimiter)).toThrow(
          ExpressJwtScopeError
        )
      }
    )
  })

  test('List of colon-separated string, returns Array of splited substrings', () => {
    const regex = '[a-z]'
    const sep = ':'
    const argList = ['read', 'user:read', 'user:post:write']
    const expected = [['read'], ['user', 'read'], ['user', 'post', 'write']]
    expect(factoryArgv(argList, regex, sep)).toEqual(expected)
  })

  test('Lixed argument list of strings and functions', () => {
    const regex = '[a-z]'
    const sep = ':'
    const callable = () => true
    const argList = ['read', callable, 'user:read']
    const expected = [['read'], callable, ['user', 'read']]

    expect(factoryArgv(argList, regex, sep)).toEqual(expected)
  })
})

describe('parseGrantedScope helper function', () => {
  test('granted scope has wrong claim delimiter, throws InternalServerError', () => {
    const scope = 'user:read user:write'
    const claimDelimiter = ','
    const claimCharset = '[a-z]'
    const claimScopeDelimiter = ':'
    expect(() =>
      parseGrantedScope(
        scope,
        claimDelimiter,
        claimCharset,
        claimScopeDelimiter
      )
    ).toThrow(InternalServerError)
  })

  test('granted scope has wrong claim scope delimiter, throws InternalServerError', () => {
    const scope = 'user:read user:write'
    const claimDelimiter = ' '
    const claimCharset = '[a-z]'
    const claimScopeDelimiter = '.'

    expect(() =>
      parseGrantedScope(
        scope,
        claimDelimiter,
        claimCharset,
        claimScopeDelimiter
      )
    ).toThrow(InternalServerError)
  })

  describe('granted scope badly formated string, throws InternalServerError', () => {
    const claimDelimiter = ','
    const claimCharset = '[a-z]'
    const claimScopeDelimiter = ':'

    test.each([
      ['scope has trailing spaces', ' read,write '],
      ['scope has trailing delimiter', 'read,write,'],
      ['permission value has trailing spaces', 'read, write']
    ])("%s: '%s'", (_, scope) => {
      expect(() =>
        parseGrantedScope(
          scope,
          claimDelimiter,
          claimCharset,
          claimScopeDelimiter
        )
      ).toThrow(InternalServerError)
    })
  })

  describe('granted permission has unsupported characters, throws InternalServerError', () => {
    const claimDelimiter = ','
    const claimCharset = '[a-z]'
    const claimScopeDelimiter = ':'

    test.each(['чтение', '*,user', ['user-post:delete']])('%s', scope => {
      expect(() =>
        parseGrantedScope(
          scope,
          claimDelimiter,
          claimCharset,
          claimScopeDelimiter
        )
      ).toThrow(InternalServerError)
    })
  })

  describe('parse supported granted scope, returns string[][]', () => {
    const scope = ['read', 'user:delete', 'post:*:delete']
    const claimCharset = '[a-z]'
    const claimScopeDelimiter = ':'
    const expected = [['read'], ['user', 'delete'], ['post', '*', 'delete']]

    test('granted scope is a string', () => {
      const claimDelimiter = '"'

      expect(
        parseGrantedScope(
          scope.join(claimDelimiter),
          claimDelimiter,
          claimCharset,
          claimScopeDelimiter
        )
      ).toEqual(expected)
    })

    test('granted scope as an array', () => {
      const claimDelimiter = ','

      expect(
        parseGrantedScope(
          scope,
          claimDelimiter,
          claimCharset,
          claimScopeDelimiter
        )
      ).toEqual(expected)
    })

    test('granted scope is an empty array', () => {
      expect(parseGrantedScope([])).toEqual([])
    })
  })
})
