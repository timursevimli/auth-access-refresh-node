'use strict';

const http = require('node:http');
const querystring = require('node:querystring');
const { createSigner, createVerifier } = require('fast-jwt');
const { LRUCache } = require('lru-cache');
const { generateToken } = require('./crypto.js');

const PORT = 34777;
const SESSION_EXPIRE = 60_000;
const ACCESS_EXPIRE = '30s';
const CACHE_SIZE = 100;
const EXPIRED_COOKIE = 'Thu, 01 Jan 1970 00:00:00 GMT';
const ALLOWED_URL = 'http://localhost:3000';
const { SECRET = 'most-secret-key' } = process.env;

const cache = new LRUCache({
  max: CACHE_SIZE,
  ttl: SESSION_EXPIRE,
});

const signSync = createSigner({ key: SECRET, expiresIn: ACCESS_EXPIRE });
const verifySync = createVerifier({ key: SECRET });

const users = [
  {
    id: 1,
    username: 'admin',
    password: 'admin',
    roles: ['admin'],
    status: 'active',
  },
  {
    id: 2,
    username: 'editor',
    password: 'editor',
    roles: ['editor'],
    status: 'active',
  },
];

const HEADERS = [
  ['X-XSS-Protection', '1; mode=block'],
  ['X-Content-Type-Options', 'nosniff'],
  ['Strict-Transport-Security', 'max-age=31536000; includeSubdomains; preload'],
  ['Access-Control-Allow-Origin', ALLOWED_URL],
  ['Access-Control-Allow-Methods', 'POST, GET, OPTIONS'],
  ['Access-Control-Allow-Headers', 'Content-Type, Authorization'],
  ['Access-Control-Allow-Credentials', 'true'],
];

const parseHost = (host) => {
  if (!host) return 'no-host-name-in-http-headers';
  const portOffset = host.indexOf(':');
  if (portOffset > -1) host = host.substr(0, portOffset);
  return host;
};

const getExpireDate = (days = 14) => {
  const date = new Date();
  date.setDate(date.getDate() + days);
  return date.toUTCString();
};

const getRefreshCookie = (
  req,
  val,
  { expired = false, httpOnly = true, secure = true, sameSite = 'strict' } = {},
) => {
  const expires = `expires=${expired ? EXPIRED_COOKIE : getExpireDate()}`;
  const host = req.headers['host'];
  const domain = parseHost(host);
  let cookie = `token=${val}; ${expires}; Path=/; Domain=${domain}`;
  if (httpOnly) cookie += '; HttpOnly';
  if (secure) cookie += '; Secure';
  if (sameSite) cookie += `; SameSite=${sameSite}`;
  return cookie;
};

const parseCookie = (headers = {}) => {
  const { cookie } = headers;
  if (!cookie) return {};
  const cookies = querystring.parse(cookie, '; ');
  return cookies;
};

const findUserById = (id = 0) =>
  new Promise((resolve) => {
    const result = users.find((u) => u.id === id) || null;
    setTimeout(resolve, 0, result);
  });

const findUserByName = (username = '') =>
  new Promise((resolve) => {
    const result = users.find((u) => u.username === username) || null;
    setTimeout(resolve, 0, result);
  });

const sendResponse = (res = null, code = 200, data = {}, headers = {}) => {
  res
    .writeHead(code, { 'Content-Type': 'application/json', ...headers })
    .end(JSON.stringify(data));
};

const getBody = async (req) => {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  return JSON.parse(Buffer.concat(chunks).toString() || '{}');
};

const isAuthorized = (headers, acceptableRole = 'user') => {
  const authorization = headers['authorization'];
  if (!authorization) return false;
  try {
    const [type, token] = authorization.split(' ');
    if (type !== 'Bearer' || !token) return false;
    const { roles = [] } = verifySync(token);
    for (let role of roles) {
      if (role === acceptableRole || role === 'admin') {
        return true;
      }
    }
    return false;
  } catch (err) {
    console.error(err);
    return false;
  }
};

const routing = {
  '/': '<h1>welcome to my server</h1>',
  '/auth/signup': async (req, res) => {
    const cookies = parseCookie(req.headers);
    const refreshToken = cookies.token;
    if (refreshToken) cache.delete(refreshToken);
    const body = await getBody(req);
    if (!body) return void sendResponse(res, 400, { message: 'Bad request' });
    const { username, password } = body;
    if (!username || !password) {
      return void sendResponse(res, 400, { message: 'Bad request' });
    }
    const user = await findUserByName(username);
    if (user) {
      return void sendResponse(res, 409, { message: 'User already exists' });
    }
    users.push({
      username,
      password,
      roles: ['user'],
      id: users.length + 1,
      status: 'active',
    });
    sendResponse(res, 201, 'Successfully registered');
  },
  '/auth/signin': async (req, res) => {
    const cookies = parseCookie(req.headers);
    const refreshToken = cookies.token;
    if (refreshToken) cache.delete(refreshToken);
    const body = await getBody(req);
    if (!body) return void sendResponse(res, 400, { message: 'Bad request' });
    const { username, password } = body;
    if (!username || !password) {
      return void sendResponse(res, 400, { message: 'Bad request' });
    }
    const user = await findUserByName(username);
    if (!user || user.password !== password) {
      return void sendResponse(res, 401, {
        message: 'Wrong username or password',
      });
    }
    const { id, roles, status } = user;
    if (status !== 'active') {
      return void sendResponse(res, 401, { message: 'User is inactive' });
    }
    try {
      const accessToken = signSync({ id, roles });
      const refreshToken = generateToken(password);
      cache.set(refreshToken, { id });
      sendResponse(
        res,
        200,
        { username, roles, accessToken },
        {
          'Set-Cookie': getRefreshCookie(req, refreshToken),
        },
      );
    } catch (err) {
      console.error(err);
      sendResponse(res, 500, { message: 'Internal server error' });
    }
  },
  '/auth/signout': async (req, res) => {
    const cookies = parseCookie(req.headers);
    if (!cookies.token) {
      return void sendResponse(res, 401, { message: 'Unauthorized' });
    }
    cache.delete(cookies.token);
    sendResponse(
      res,
      200,
      { message: 'Successfully logged out' },
      { 'Set-Cookie': getRefreshCookie(req, cookies.token, { expired: true }) },
    );
  },
  '/auth/refresh': async (req, res) => {
    const cookies = parseCookie(req.headers);
    const refreshToken = cookies.token;
    if (!refreshToken) {
      return void sendResponse(res, 401, { message: 'Unauthorized' });
    }
    const cached = cache.get(refreshToken);
    if (!cached) {
      return void sendResponse(res, 401, { message: 'Unauthorized' });
    }
    cache.delete(refreshToken);
    const user = await findUserById(cached.id);
    const { username, id, password: secret, roles, status } = user;
    if (status !== 'active') {
      return void sendResponse(res, 401, { message: 'Unauthorized' });
    }
    try {
      const accessToken = signSync({ id, roles });
      const refreshToken = generateToken(secret);
      cache.set(refreshToken, { id });
      sendResponse(
        res,
        200,
        { username, roles, accessToken },
        {
          'Set-Cookie': getRefreshCookie(req, refreshToken),
        },
      );
    } catch (err) {
      console.error(err);
      sendResponse(res, 500, { message: 'Internal server error' });
    }
  },
  '/dashboard': (req, res) => {
    const authorized = isAuthorized(req.headers, 'user');
    if (authorized) {
      sendResponse(200, { message: 'Dashboard (only for users)' });
    } else {
      sendResponse(res, 401, { message: 'Unauthorized' });
    }
  },
  '/users': (req, res) => {
    const authorized = isAuthorized(req.headers, 'admin');
    if (!authorized) sendResponse(res, 401, 'Unauthorized');
    else sendResponse(res, 200, users);
  },
  '/cookies': async (req, res) => {
    sendResponse(res, 200, querystring.parse(req.headers.cookie, '; '));
  },
};

const types = {
  object: (o) => [200, JSON.stringify(o)],
  string: (s) => [200, s],
  undefined: () => [404, 'Page not found'],
  function: (fn, req, res) => void fn(req, res),
};

const server = http.createServer((req, res) => {
  const { method, url } = req;
  console.log(`${method} ${url}`);
  for (const [header, value] of HEADERS) res.setHeader(header, value);
  if (method === 'OPTIONS') return void res.writeHead(204).end();
  const data = routing[url];
  const type = typeof data;
  const serializer = types[type];
  const result = serializer(data, req, res);
  if (!result) return;
  const [code, response] = result;
  const contentType = type === 'object' ? 'application/json' : 'text/html';
  res.writeHead(code, { 'Content-Type': contentType }).end(response);
});

server
  .on('listening', () => {
    const { port } = server.address();
    console.log(`listening on http://localhost:${port}`);
  })
  .listen(PORT);
