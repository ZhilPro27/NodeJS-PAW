const detailPembelian = require('./detailPembelianModel');
const db = require('../Database/db');

// Menggunakan mock database dari folder __mocks__
jest.mock('../Database/db');

describe('Detail Pembelian Model (Callback)', () => {

  // Membersihkan mock setelah setiap pengujian
  beforeEach(() => {
    db.query.mockClear();
  });

  /**
   * Test Case 1: Menguji fungsi getAllDetailPembelian
   * Memastikan fungsi berhasil mengambil semua data detail pembelian.
   */
  test('should fetch all purchase details', (done) => {
    // Arrange: Siapkan data tiruan
    const mockDetails = [
      { idDetailPembelian: 'DP-0001', idPembelian: 'P-001' },
      { idDetailPembelian: 'DP-0002', idPembelian: 'P-001' },
    ];
    
    // Atur mock agar memanggil callback dengan data tiruan (tanpa error)
    db.query.mockImplementation((sql, callback) => {
      callback(null, mockDetails);
    });

    // Act: Jalankan fungsi yang diuji
    detailPembelian.getAllDetailPembelian((err, details) => {
      // Assert: Periksa hasilnya di dalam callback
      expect(err).toBeNull();
      expect(details).toHaveLength(2);
      expect(details[0].idPembelian).toBe('P-001');
      expect(db.query).toHaveBeenCalledWith("SELECT * FROM detail_pembelian", expect.any(Function));
      
      // Beritahu Jest bahwa test asynchronous ini sudah selesai
      done();
    });
  });

  /**
   * Test Case 2: Menguji fungsi getDetailPembelianById
   * Memastikan fungsi berhasil menemukan satu data detail berdasarkan ID.
   */
  test('should fetch a single purchase detail by its ID', (done) => {
    // Arrange: Siapkan data tiruan untuk satu item
    const mockDetail = [{ idDetailPembelian: 'DP-0003', idPembelian: 'P-002' }];
    const targetId = 'DP-0003';

    // Atur mock agar memanggil callback dengan data tiruan
    db.query.mockImplementation((sql, params, callback) => {
      // Pastikan parameter ID yang dikirim benar
      if (params[0] === targetId) {
        callback(null, mockDetail);
      }
    });

    // Act: Jalankan fungsi yang diuji dengan ID target
    detailPembelian.getDetailPembelianById(targetId, (err, result) => {
      // Assert: Periksa hasilnya
      // Kode Anda langsung meneruskan hasil dari db.query, jadi hasilnya adalah array
      expect(err).toBeNull();
      expect(result).toBeInstanceOf(Array);
      expect(result[0].idDetailPembelian).toBe(targetId);
      expect(db.query).toHaveBeenCalledWith("SELECT * FROM detail_pembelian WHERE id = ?", [targetId], expect.any(Function));

      // Beritahu Jest bahwa test sudah selesai
      done();
    });
  });
});