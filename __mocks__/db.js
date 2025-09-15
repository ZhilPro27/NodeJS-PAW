
const db = {
  query: jest.fn(),
  getConnection: jest.fn(),
  promise: function() { return this; }
};

module.exports = db;