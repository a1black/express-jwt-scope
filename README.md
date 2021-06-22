# express-jwt-scope

Express middleware that checks JWT for permissions to access protected end-point.

## Installation

```
npm install --save a1black/express-jwt-scope
```

## Granted permissions

- Access token **should be** plain JSON serializable object. Module uses JSON serialization to copy the access token before passing it to custmon permission checker.
- Admin claim **should have** value of `true` or `1`, anything else is considered to be `false`.
- Granted permissions **must be** described as an array or as a string of delimiter-separated values.
- Permission **must be** a string of delimiter-separated values, where the first value is permission's name and all subsequent are permission's scope.
- Permission's name **must be** alphanumeric (and `_`) case-sensitive ASCII string.
- Permission's scope **must be** alphanumeric (and `_`) case-sensitive ASCII string or `*` that matches any requested scope.
- Wildcard scope **is explicit**, i.e. `user` and `user:*` are not the same.

_Wildcard scope_ matching rules:

| Requested  | Granted  | Result                              |
| ---------- | -------- | ----------------------------------- |
| `user`     | `user:*` | `true`                              |
| `user:add` | `user:*` | `true`                              |
| `user:add` | `user`   | `false`                             |
| `user:*`   | `user`   | error, invalid requested permission |

## Usage

This middleware assumes that request object already has decoded token payload attached to it by one of request handlers prior in the middleware chain (like [express-jwt][]).

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

| Name                    | Default     | Description                                                                                                   |
| ----------------------- | ----------- | ------------------------------------------------------------------------------------------------------------- |
| **tokenKey**            | `user`      | Path to the decoded token (utilizes [lodash.get]()).                                                          |
| **scopeKey**            | `scope`     | Path to the granted permissions inside the token (utilizes [lodash.get][]).                                   |
| **adminKey**            | `undefined` | Path to the admin claim inside the token (utilizes [lodash.get][]) or a callback                              |
| **claimDelimiter**      | `,`         | ASCII punctuation\* character (or space) used if granted permissions described as character-delimited string. |
| **claimScopeDelimiter** | `:`         | ASCII punctuation\* character that separates permission name and its scope.                                   |

\* Punctuation characters are \-\!\"\#\$\%\&\'\(\)\+\,\.\/\:\;\<\=\>\?\@\[\]\^\`\{\|\}\~

### Error handling

If permission check fails middleware will throw `ForbiddenError` with `status` property set to `403` which can be handled by Express default error handler.

**Note**: Middleware produced by this library is `async` function that doesn't explicitly passes error to the `next()`. Which means, you must promisify method ([see below](#promisify)) or use Express 5.

## API

### middleware(...permissions)

Sets list of permissions, all of which are required to pass authorization check. Argument's value **must be** a permission string or a function. Permissions are evaluated in the order which they are recieved.

If **adminKey** is set, middleware doesn't require any arguments, otherwise at least one argument required.

Permission string is a delimiter-separated string, where first value is permission's name and all subsequent are permission's scope. Permission's name and scope **must be** alphanumeric (and `_`) case-sensitive ASCII string (wildcard scope are illegal).

Function passed to the middleware **should have** signature `(scope, helpers) => boolean`, where:

- **scope** {string[][]} - An array produced by spliting granted permissions string using `claimDelimiter` and further spliting elements in resulting array using `claimScopeDelimiter`.
- **helpers** {object}
  - `error(message)` - function that throws `ForbiddenError` with `message`.
  - req - reference to HTTP request object.
  - claimDelimiter - [see configuration](#configuration)
  - claimScopeDelimiter - [see configuration](#configuration)
  - isAdmin - set to `true` if the access token possesses admin claim, `false` otherwise.
  - originScope - copy of permission field found in the access token.
  - token - copy of the access token.

```js
const jwtScope = require('express-jwt-scope')({ adminKey: 'admin' })
// Admin only.
app.get('/admin', jwtScope())
// Grand access if editing own profile.
app.get(
  '/profile/:id',
  jwtScope((scope, { req, token }) => req.params.id === token.sub)
)
```

### or(permission, ...restPermissions)

Adds alternative set of permissions to check if previous one failed.

```js
const jwtScope = require('express-jwt-scope')()
// Grand access if 'write' OR 'user:write' OR callable()
app.use(jwtScope('write').or('user:write').or(function (scope, helpers) { ... }))
```

### not(permisson, ...restPermissions)

Adds check that none of permissions are present in the granted permissions.

```js
const jwtScope = require('express-jwt-scope')()
// Grand access if ('read' AND 'write') AND !('get' AND 'put')
app.use(jwtScope('read', 'write').not('get', 'put'))
```

### promisify()

Returns wrapper function that properly handles async exceptions.

```js
const jwtScope = require('express-jwt-scope')()
app.use(jwtScope('write').promisify())
```

[express-jwt]: https://github.com/auth0/express-jwt#readme
[lodash.get]: https://lodash.com/docs/4.17.15#get 'lodash.get'
