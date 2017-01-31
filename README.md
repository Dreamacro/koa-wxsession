# koa-wxsession

Wechat session authorization and validation middleware for koa@2

## Koa2

中间件采用 `async/await` 关键字, 所以使用环境必须使用 Node.js >= 7.0.0 的版本(暂时需要 `--harmony_async_await` 参数) 或者使用 `babel`

## Installation

```js
$ npm install koa-wxsession
```

## Example

```js
const Koa = require('koa')
const router = require('koa-router')()
const app = new Koa()
const wxsession = require('koa-wxsession')

const { authorization, validation } = wxsession({
    appID: 'appID',
    appSecret: 'appSecret',
    // https://www.npmjs.com/package/redis#options-object-properties
    redisConfig: {},
	generator: code => { /* generator your session */ },
    errors: {
    	'ERR_HEADER_MISSED': ctx => ctx.throw(400, 'an error')
    }
})

router
    .post('/auth', authorization, ctx => ctx.body = { session: ctx.state.wxinfo.session })
    .get('/secret', validation, ctx => ctx.body = ctx.state.wxinfo)

app.use(router.routes())

app.listen(3000, _ => console.log('listening on port 3000'))
```

## Options

* `appID` 微信小程序的 appID
* `appSecret` 微信小程序的 appSecret
* `store` 存储 Session 的 自定义 store，详细格式请看 `lib/lru-cache.js` 和  `lib/redis.js` 
* `prefix` store 里 key 的前缀 [wx-session:]
* `ttl` Session 过期时间(毫秒) [2 * 60 * 60 * 1000]
* `redisConfig` 使用 `Redis` 作为 Session store，若不填则使用 `lru-cache`
* `stateKey` `ctx.state` 里存储的 key 的名字 [wxinfo]
* `generator` Session 生成函数 [code => sha1(code)]
* `useEncryptedData` 替代 `rawData` 使用 `encryptedData` [false]
* `errors`
  * `ERR_HEADER_MISSED` 缺少 header 时的回调函数
  * `ERR_SESSION_KEY_EXCHANGE_FAILED` `code` 错误或请求失败的回调函数
  * `ERR_UNTRUSTED_DATA` 请求的 `Data` 验证或解密失败的回调函数
  * `ERR_SESSION_INVALID` Session 验证失败的回调函数
  * `ERR_OTHERS` 其他错误的回调函数

## License

  MIT