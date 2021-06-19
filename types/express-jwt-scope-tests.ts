import express = require('express');
import expressJwtScope = require('express-jwt-scope');

const app = express();
const middleware = expressJwtScope({
  adminClaimEnabled: true,
  claimDelimiter: ',',
  claimScopeDelimiter: ':',
  scopeKey: 'scope',
  scopeRequired: false,
  tokenKey: 'user'
});

app.use(middleware());
app.use(middleware('read', 'write'));
app.use(middleware((scope, helpers) => true, scope => true, () => true));
app.use(middleware('read').or('write').or('delete'));
app.use(middleware('read').not('write').not('delete'));
app.use(middleware(scope => true).or(scope => true).not(scope => true));
app.use(middleware('read').promisify());
