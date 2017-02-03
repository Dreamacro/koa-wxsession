const redis = require('./lib/redis')
const lru = require('./lib/lru-cache')
const debug = require('debug')('koa-wxsession')
const getSessionKey = require('./lib/sessionkey')
const sha1 = require('./lib/sha1')
const ERRORS = require('./constants').errors
const wrapError = require('./lib/warpError')
const aesDecrypt = require('./lib/aes')

module.exports = wxsession

function wxsession ({
    appID,
    appSecret,
    store,
    prefix = 'wx-session:',
    ttl = 2 * 60 * 60 * 1000,
    redisConfig,
    stateKey = 'wxinfo',
    generator = code => sha1(code),
    useEncryptedData = false,
    errors = {
        [ERRORS.ERR_HEADER_MISSED]: wrapError(400, ERRORS.ERR_HEADER_MISSED),
        [ERRORS.ERR_SESSION_KEY_EXCHANGE_FAILED]: wrapError(400, ERRORS.ERR_SESSION_KEY_EXCHANGE_FAILED),
        [ERRORS.ERR_UNTRUSTED_DATA]: wrapError(400, ERRORS.ERR_UNTRUSTED_DATA),
        [ERRORS.ERR_SESSION_INVALID]: wrapError(401, ERRORS.ERR_SESSION_INVALID),
        [ERRORS.ERR_OTHERS]: wrapError(500, ERRORS.ERR_OTHERS)
    }
}) {
    store = store || (redisConfig ? redis(ttl, redisConfig) : lru(ttl))

    return {
        authorization: async (ctx, next) => {
            const {
                'x-wechat-code': code,
                'x-wechat-data': data,
                'x-wechat-signature': signature,
                'x-wechat-encrypted': encryptedData,
                'x-wechat-iv': iv
            } = ctx.headers
            const rawData = decodeURIComponent(data || '')

            // header check
            if (useEncryptedData) {
                if ([code, encryptedData, iv].some(v => !v)) {
                    debug(ERRORS.ERR_HEADER_MISSED)
                    return errors[ERRORS.ERR_HEADER_MISSED](ctx)
                }
            } else {
                if ([code, rawData, signature].some(v => !v)) {
                    debug(ERRORS.ERR_HEADER_MISSED)
                    return errors[ERRORS.ERR_HEADER_MISSED](ctx)
                }
            }

            // session exchange
            debug('code: %s', code)
            try {
                var {openid, session_key} = await getSessionKey(appID, appSecret, code)
                debug('openid: %s, session_key: %s', openid, session_key)
            } catch (e) {
                debug('%s: %s', ERRORS.ERR_SESSION_KEY_EXCHANGE_FAILED, e.message)
                return errors[ERRORS.ERR_SESSION_KEY_EXCHANGE_FAILED](ctx)
            }

            // decrypt or signature check
            let decryptedData
            if (useEncryptedData) {
                try {
                    decryptedData = aesDecrypt(session_key, iv, encryptedData)
                } catch (e) {
                    debug(ERRORS.ERR_UNTRUSTED_DATA)
                    return errors[ERRORS.ERR_UNTRUSTED_DATA](ctx)
                }
            } else {
                if (sha1(rawData + session_key) !== signature) {
                    debug(ERRORS.ERR_UNTRUSTED_DATA)
                    return errors[ERRORS.ERR_UNTRUSTED_DATA](ctx)
                }
            }

            // store session
            try {
                const session = generator(code)
                const key = prefix + session
                const info = {
                    openid,
                    info: useEncryptedData ? JSON.parse(decryptedData) : JSON.parse(rawData),
                    session
                }
                await store.set(key, info)
                ctx.state[stateKey] = info
            } catch (e) {
                debug('%s: %s', ERRORS.ERR_OTHERS, e.message)
                return errors[ERRORS.ERR_OTHERS](ctx)
            }
            return next()
        },
        validation: async (ctx, next) => {
            // check session
            const session = ctx.headers['x-wechat-session']
            if (!session) {
                debug(ERRORS.ERR_SESSION_INVALID)
                return errors[ERRORS.ERR_SESSION_INVALID](ctx)
            }
            const key = prefix + session
            try {
                const ret = await store.get(key)
                if (ret == null) {
                    debug(ERRORS.ERR_SESSION_INVALID)
                    return errors[ERRORS.ERR_SESSION_INVALID](ctx)
                }
                ctx.state[stateKey] = ret
            } catch (e) {
                debug('%s: %s', ERRORS.ERR_OTHERS, e.message)
                return errors[ERRORS.ERR_OTHERS](ctx)
            }
            return next()
        }
    }
}
