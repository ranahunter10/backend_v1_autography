const asyncHandler = (requestHandler) => {
  return (req, res,next) => {
      Promise.resolve(requestHandler(req, res, next)).catch((err) => next(err))
  }
}


export { asyncHandler }

// for understanding purpose ---->
// const asyncHandler = () => {}
// const asyncHandler = (func) => () => {}
// const asyncHandler = (func) => async () => {}
