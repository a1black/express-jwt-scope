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
      adminKey: undefined,
      claimDelimiter: ',',
      claimScopeDelimiter: ':',
      scopeKey: 'scope',
      tokenKey: 'user'
    })
  })
})

describe('factoryArgv helper function', () => {
  test('Empty argument list, throws ExpressJwtScopeError', () => {
    expect(() => factoryArgv([])).toThrow(ExpressJwtScopeError)
  })

  describe('Invalid argument, throws ExpressJwtScopeError', () => {
    test.each([null, true, 1000, '', 'read,write', ['read'], { read: true }])(
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

  describe("Unsupported characters in argument's value, throws ExpressJwtScopeError", () => {
    test.each(['user-posts:delete', 'user:*', 'чтение'])('%s', value => {
      const regex = '[a-z]'
      const delimiter = ':'
      expect(() => factoryArgv([value], regex, delimiter)).toThrow(
        ExpressJwtScopeError
      )
    })
  })

  test('String or function argument expected, returns array', () => {
    const regex = '[a-z]'
    const sep = ':'
    const callable = () => true
    const argList = ['read', 'user:read', 'user:post:write', callable]
    const expected = [
      ['read'],
      ['user', 'read'],
      ['user', 'post', 'write'],
      callable
    ]

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

    describe('granted scope is empty value, returns an empty array', () => {
      test.each([undefined, '', []])('%s', scope => {
        expect(parseGrantedScope(scope)).toEqual([])
      })
    })
  })
})
