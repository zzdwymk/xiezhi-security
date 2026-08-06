class UserFacingError extends Error {
  constructor(message) {
    super(message);
    this.name = this.constructor.name;
  }
}

function publicErrorMessage(error, fallback) {
  if (error instanceof UserFacingError && error.message.trim())
    return error.message.trim();
  return fallback;
}

function diagnosticError(error) {
  if (error instanceof Error) return `${error.name}: ${error.message}`;
  return String(error);
}

module.exports = { UserFacingError, diagnosticError, publicErrorMessage };
