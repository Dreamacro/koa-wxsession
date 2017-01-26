const crypto = require('crypto')

module.exports = str => crypto.createHash('sha1').update(str).digest('hex')
