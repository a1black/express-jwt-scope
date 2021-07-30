import express = require('express');
import expressJwtScope = require('express-jwt-scope');

const app = express();
const middleware = expressJwtScope({
  adminKey: 'admin',
  claimDelimiter: ',',
  claimScopeDelimiter: ':',
  credentialsRequired: true,
  requestProperty: 'permissions',
  scopeKey: 'scope',
  tokenKey: 'user'
});

app.use(middleware());
app.use(middleware('read', 'write'));
app.use(middleware((scope, helpers) => true));
app.use(middleware(
  (scope, helpers) => {
    return !!(
      helpers.req ||
      helpers.isAdmin ||
      helpers.token
    );
  })
);
app.use(middleware('read').or('write').or('delete'));
app.use(middleware('read').not('write').not('delete'));
app
  .use(middleware('read', scope => true)
  .or('read', scope => true)
  .not('read', scope => true));
app.use(middleware('read').promisify());

app.use((req, res, next) => {
  req.permissions?.isAdmin();
  req.permissions?.hasPermission((scope, helpers) => true);
  req.permissions?.hasPermission('read').then(res => res).catch(err => err);
  next();
});
