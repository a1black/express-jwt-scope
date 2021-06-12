# express-jwt-scope

Express middleware that checks JWT for permissions to access protected end-point.

## Installation

```
npm install --save a1black/express-jwt-scope
```

## Requirements

In order to use this middleware authorization system must meet following conditions:
 - **permission string** must be formatted as: *`{name}[{delimiter}{scope}[...]]`*, where
   - *name* - alphanumeric (and `_`) case-sensitive **ASCII** string
   - *delimiter* - **ASCII** punctuation character (except `*` and `_`)
   - *scope* - alphanumeric (and `_`) case-sensitive **ASCII** string or `*` character for granted permissions only.
 - **granted permissions** must be described as an array of permission strings, or as a character-delimited string: *`{permission}[{delimiter}{permission}[...]]`*, where
   - *delimiter* - **ASCII** punctuation character (except `*` and `_`) or single space
 - **granted permissions** must use explicit scoping, i.e. `user` does not include `user:read`, but `user:*` does. It also means, `user` and `user:*` are different permissions.

## Usage
This middleware assumes that request object already has decoded token payload attached to it and permission claim in the access token meets requirements.

```js
const jwt = require('express-jwt');
const jwtScope = require('express-jwt-scope')({ scopeKey: 'permissions' });

app.get(
  '/protected',
  jwt({ secret: 'secret', algorithms: ['HS256'] }),
  // Grand access if ('read' OR ('user:read' AND 'user:write')) AND !(callback())
  jwtScope('read').or('user:read', 'user:write').not(function (scope, helpers) { ... }),
  (req, res, next) => { res.sendStatus(200); }
)
```
 ### Configuration

| Name | Default | Description |
| ---- | ------- | ----------- |
| **tokenKey** | `user` | Path to the decoded token (utilizes [lodash.get][]).|
| **scopeKey** | `scope` | Path to the granted permissions inside the token (utilizes [lodash.get][]). |
| **scopeRequired** | `true` | If `false` then empty or `undefined` scope value won't immediately trigger error, usefull if requested permissions are user defined functions. |
| **adminClaimEnabled** | `false` | If `true` then look for `admin` string in granted permission and if found grand access regardless to other requested permissoins. |
| **claimDelimiter** | `,` | ASCII punctuation\* character (or space) used if granted permissions described as character-delimited string. |
| **claimScopeDelimiter** | `:` | ASCII punctuation\* character that separates permission name and its scope. |

\* valid punctuation characters are *\-\!\"\#\$\%\&\'\(\)\+\,\.\/\:\;\<\=\>\?\@\[\]\^\`\{\|\}\~*

\*\* fullpath to the granted permissions is `tokenKey` + `scopeKey`

### Error handling

If none of requested permissions found in the access token, middleware throws `ForbiddenError` with `status` property set to `403` which can be handled by Express default error handler.

**Note**: Middleware produced by this library is `async` function that doesn't explicitly passes error to the `next()`. Which means, you must promisify middleware function ([see below](#promisify)) or use Express 5.

## API

### middleware(...args)

Sets list of permissions, all of which are required to pass authorization check. Argument's value must be a `permission string` as [described above][#requirements] or a function. Permissions are evaluated in the order they passed to the middleware.

Function passed to the middleware should have signature `(scope, helpers) => boolean`, where:
 - **scope** (string[][]) - An array produced by spliting granted permissions string using `claimDelimiter` and further spliting elements in resulting array using `claimScopeDelimiter`.
 - **helpers**
   - `error(message)` - function that throws `ForbiddenError` with `message`.
   - req - reference to HTTP request object.
   - scope - copy of permission field found in the access token.
   - token - copy of the access token.

```js
const jwtScope = require('express-jwt-scope')()
// Grand access if has 'user:write' privilage or is editing own profile.
app.get('/profile/:id', jwtScope('user:write').or((scope, { req, token }) => {
  return req.params.id === token.sub
}))
```

### or(...args)

Adds alternative set of permissions to check if previous one failed.

```js
const jwtScope = require('express-jwt-scope')()
// Grand access if 'write' OR 'user:write' OR callable()
app.use(jwtScope('write').or('user:write').or(function (scope, helpers) { ... }))
```

### not(...args)

Adds check that none of permissions in `args` present in the granted permissions.

```js
const jwt = require('express-jwt-scope')()
// Grand access if ('read' AND 'write') AND !('user:read' AND 'user:write')
app.use(jwtScope('read', 'write').not('user:read', 'user:write'))
```

### promisify()

Method returns promise with rejection handler as follows `.catch(next)`.

[lodash.get]: https://lodash.com/docs/4.17.15#get 'lodash.get'