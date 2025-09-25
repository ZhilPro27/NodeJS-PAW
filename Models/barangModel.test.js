const Barang = require('../barangModel');
const db = require('../../Database/db');

jest.mock('../../Database/db', () => ({
  query: jest.fn(),
}));

describe('Barang Model', () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  test('getBarangById should query barang by id', (done) => {
    const mockResult = [{ idBarang: 'B-001', namaBarang: 'Pensil' }];
    db.query.mockImplementation((query, params, callback) => {
      callback(null, mockResult);
    });

    Barang.getBarangById('B-001', (err, result) => {
      expect(err).toBeNull();
      expect(result).toEqual(mockResult);
      expect(db.query).toHaveBeenCalledWith(
        'SELECT * FROM barang WHERE idBarang = ?',
        ['B-001'],
        expect.any(Function)
      );
      done();
    });
  });
});