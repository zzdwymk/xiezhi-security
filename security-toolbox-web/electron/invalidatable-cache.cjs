function createInvalidatableCache(load) {
  let initialized = false;
  let value;

  return {
    get() {
      if (!initialized) {
        value = load();
        initialized = true;
      }
      return value;
    },
    replace(nextValue) {
      value = nextValue;
      initialized = true;
      return value;
    },
    invalidate() {
      initialized = false;
      value = undefined;
    },
  };
}

module.exports = { createInvalidatableCache };
