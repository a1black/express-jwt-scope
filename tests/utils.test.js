const { factoryArgv, moduleArgv, parseGrantedScope } = require('../utils')

describe('moduleArgv helper function', () => {
  test.each([
    ['invalid delimiter character', { claimDelimiter: '_' }],
    ['too long delimiter string', { claimDelimiter: '::' }],
    [
      'duplicating delimiters',
      { claimDelimiter: ',', claimScopeDelimiter: ',' }
    ]
  ])('%s, throws Error', (_, options) => {
    expect(() => moduleArgv(options)).toThrow(Error)
  })

  test('configuration defaults, returns object', () => {
    expect(moduleArgv()).toMatchObject({
      adminKey: undefined,
      claimDelimiter: ',',
      claimScopeDelimiter: ':',
      credentialsRequired: true,
      requestProperty: 'permissions',
      scopeKey: 'scope',
      tokenKey: 'user'
    })
  })
})

describe('factoryArgv helper function', () => {
  test('Empty argument list, throws Error', () => {
    expect(() => factoryArgv([])).toThrow('Expected at least one argument')
  })

  describe('Invalid argument, throws Error', () => {
    test.each([null, true, 1000, '', 'read,write', ['read'], { read: true }])(
      '%s',
      value => {
        const regex = '[a-z]'
        const delimiter = ':'
        expect(() => factoryArgv([value], regex, delimiter)).toThrow(Error)
      }
    )
  })

  describe("Unsupported characters in argument's value, throws Error", () => {
    test.each(['user-posts:delete', 'user:*', 'чтение'])('%s', value => {
      const regex = '[a-z]'
      const delimiter = ':'
      expect(() => factoryArgv([value], regex, delimiter)).toThrow(Error)
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
  test('granted scope has wrong claim delimiter, returns null', () => {
    const scope = 'user:read user:write'
    const claimDelimiter = ','
    const claimCharset = '[a-z]'
    const claimScopeDelimiter = ':'
    expect(
      parseGrantedScope(
        scope,
        claimDelimiter,
        claimCharset,
        claimScopeDelimiter
      )
    ).toBeNull()
  })

  test('granted scope has wrong claim scope delimiter, returns null', () => {
    const scope = 'user:read user:write'
    const claimDelimiter = ' '
    const claimCharset = '[a-z]'
    const claimScopeDelimiter = '.'

    expect(
      parseGrantedScope(
        scope,
        claimDelimiter,
        claimCharset,
        claimScopeDelimiter
      )
    ).toBeNull()
  })

  describe('granted scope badly formated string, returns null', () => {
    const claimDelimiter = ','
    const claimCharset = '[a-z]'
    const claimScopeDelimiter = ':'

    test.each([
      ['scope has trailing spaces', ' read,write '],
      ['scope has trailing delimiter', 'read,write,'],
      ['permission value has trailing spaces', 'read, write']
    ])("%s: '%s'", (_, scope) => {
      expect(
        parseGrantedScope(
          scope,
          claimDelimiter,
          claimCharset,
          claimScopeDelimiter
        )
      ).toBeNull()
    })
  })

  describe('granted permission has unsupported characters, returns null', () => {
    const claimDelimiter = ','
    const claimCharset = '[a-z]'
    const claimScopeDelimiter = ':'

    test.each(['чтение', '*,user', ['user-post:delete']])('%s', scope => {
      expect(
        parseGrantedScope(
          scope,
          claimDelimiter,
          claimCharset,
          claimScopeDelimiter
        )
      ).toBeNull()
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
