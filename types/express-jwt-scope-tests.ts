import express = require('express');
import expressJwtScope = require('express-jwt-scope');

const app = express();
const middleware = expressJwtScope({
  adminKey: 'admin',
  claimDelimiter: ',',
  claimScopeDelimiter: ':',
  scopeKey: 'scope',
  tokenKey: 'user'
});

app.use(middleware());
app.use(middleware('read', 'write'));
app.use(middleware((scope, helpers) => true));
app.use(middleware(
  (scope, helpers) => {
    return !!(
      helpers.error ||
      helpers.req ||
      helpers.claimDelimiter ||
      helpers.claimScopeDelimiter ||
      helpers.isAdmin ||
      helpers.originScope ||
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
