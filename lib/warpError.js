module.exports = (status, msg) => {
    return ctx => {
        ctx.status = status
        ctx.body = {
            msg
        }
    }
}
