'use strict'

// npm
const Boom = require('boom')
const _ = require('lodash')
const pify = require('pify')
const nano = require('cloudant-nano')

// self
const pkg = require('./package.json')

exports.register = (server, options, next) => {
  const db = nano(options.db.url)
  const auth = pify(db.auth, { multiArgs: true })
  const dbUsers = db.use('_users')
  const createUser = pify(dbUsers.insert, { multiArgs: true })
  const nextUrl = (request, reply) => reply.redirect(request.payload.next || '/')
  const selfDb = (cookie) => nano({ url: options.db.url + '/_users', cookie: cookie })

  const makeAccount = (doc, cookie) => {
    const body = _.pick(doc, ['_id', '_rev', 'name', 'roles', 'fullname'])
    body.cookie = cookie
    return body
  }

  const userSelf = (name, cookie) => {
    const dbSelf = selfDb(cookie)
    const getUser = pify(dbSelf.get, { multiArgs: true })
    return Promise.all([getUser('org.couchdb.user:' + name), cookie])
  }

  const userEdit = (request) => {
    const dbSelf = selfDb(request.auth.credentials.cookie)
    const getUser = pify(dbSelf.get, { multiArgs: true })
    const insertUser = pify(dbSelf.insert, { multiArgs: true })
    return getUser(request.auth.credentials._id)
      .then((result) => {
        if (request.payload.newpassword) {
          if (request.payload.newpassword !== request.payload.password2) { throw Boom.notAcceptable('Passwords don\'t match.') }
          result[0].password = request.payload.newpassword
        }
        if (request.payload.fullname) { result[0].fullname = request.payload.fullname }
        const account = makeAccount(result[0], result[1]['set-cookie'] || request.auth.credentials.cookie)
        return new Promise((resolve, reject) => {
          request.server.app.cache.set(account.name, { account: account }, 0, (err) => {
            if (err) { return reject(err) }
            resolve(result[0])
          })
        })
      })
      .then(insertUser)
  }

  const edit = function (request, reply) {
    userEdit(request)
      .then(() => nextUrl(request, reply))
      .catch((err) => reply.boom(err.statusCode || 500, err))
  }

  const login = function (request, reply) {
    if (request.auth.isAuthenticated) { return nextUrl(request, reply) }
    auth(request.payload.name, request.payload.password)
      .then((result) => userSelf(request.payload.name, result[1]['set-cookie']))
      .then((result) => {
        const account = makeAccount(result[0][0], result[1])
        request.server.app.cache.set(account.name, { account: account }, 0, (err) => {
          if (err) { return reply(err) }
          request.cookieAuth.set({ sid: account.name })
          nextUrl(request, reply)
        })
      })
      .catch((err) => {
        if (err.description) {
          reply.serverUnavailable(err.description)
        } else {
          reply.boom(err.statusCode || 500, err)
        }
      })
  }

  const logout = function (request, reply) {
    request.cookieAuth.clear()
    nextUrl(request, reply)
  }

  const dbDeleteUser = (request) => {
    const dbSelf = selfDb(request.auth.credentials.cookie)
    const destroyUser = pify(dbSelf.destroy, { multiArgs: true })
    return destroyUser(request.auth.credentials._id, request.auth.credentials._rev)
  }

  const deleteUser = function (request, reply) {
    dbDeleteUser(request)
      .then(() => logout(request, reply))
      .catch((err) => reply.boom(err.statusCode || 500, err))
  }

  const register = function (request, reply) {
    if (request.auth.isAuthenticated) { return nextUrl(request, reply) }
    // TODO: Use Joi validation instead
    if (request.payload.password !== request.payload.password2) { return reply.notAcceptable('Passwords don\'t match.') }
    if (!request.payload.name) { return reply.notAcceptable('Name required.') }
    if (!request.payload.password) { return reply.notAcceptable('Password required.') }
    const doc = {
      roles: [],
      _id: 'org.couchdb.user:' + request.payload.name,
      name: request.payload.name,
      password: request.payload.password,
      type: 'user'
    }
    if (request.payload.fullname) { doc.fullname = request.payload.fullname }
    createUser(doc)
      .then(() => login(request, reply))
      .catch((err) => reply.boom(err.statusCode || 500, err))
  }

  server.ext('onPreResponse', (request, reply) => {
    if (request.response.variety === 'view') {
      request.response.source.context.pathparts = request.path.split('/').slice(1)
    }
    return reply.continue()
  })

  server.register(exports.register.attributes.dependencies.map((dep) => require(dep)), (err) => {
    if (err) { throw err }
    const cache = server.cache({ segment: 'sessions', expiresIn: 30 * 24 * 60 * 60 * 1000 })
    server.app.cache = cache
    server.auth.strategy('session', 'cookie', 'try', {
      password: options.cookie.password,
      isSecure: options.cookie.secure,
      validateFunc: (request, session, callback) => {
        cache.get(session.sid, (err, cached) => {
          if (err) { return callback(err, false) }
          if (!cached) { return callback(null, false) }
          callback(null, true, cached.account)
        })
      }
    })

    server.route([
      { method: 'POST', path: '/register', handler: register },
      { method: 'POST', path: '/login', handler: login },
      {
        method: 'POST',
        path: '/edit',
        config: { auth: { mode: 'required' }, handler: edit }
      },
      {
        method: 'POST',
        path: '/logout',
        config: { auth: { mode: 'required' }, handler: logout }
      },
      {
        method: 'POST',
        path: '/delete',
        config: { auth: { mode: 'required' }, handler: deleteUser }
      }
    ])
  })

  next()
}

exports.register.attributes = {
  name: pkg.name,
  dependencies: ['hapi-boom-decorators', 'hapi-auth-cookie']
}
