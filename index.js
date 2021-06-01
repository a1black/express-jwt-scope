const middlewareFactory = () => async (req, res, next) => {
  next()
}

module.exports = middlewareFactory
