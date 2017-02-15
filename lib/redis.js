const redis = require('redis')

module.exports = (ttl, config) => {
    const client = redis.createClient(config)

    return {
        get(key) {
            return new Promise((resolve, reject) => {
                client.get(key, (err, reply) => err ? reject(err) : resolve(JSON.parse(reply)))
            })
        },
        set(key, value) {
            return new Promise((resolve, reject) => {
                client.set(key, JSON.stringify(value), 'px', ttl, (err, reply) => err ? reject(err) : resolve(reply))
            })
        }
    }
}
