const db = require('../Database/db');

const Pembelian = {
    getAllPembelian: (callback)=> {
        db.query("SELECT * FROM pembelian", callback);
    },

    getPembelianById: (id, callback) => {
        db.query("SELECT * FROM pembelian WHERE idPembelian = ?", [id], callback);
    },

    updatePembelian: (id, pembelianData, callback) => {
        db.query("UPDATE pembelian SET ? WHERE idPembelian = ?", [pembelianData, id], callback);
    },
    
    deletePembelian: (id, callback) => {
    db.beginTransaction(err => {
      if (err) {
        return callback(err, null);
      }

      const findDetailsSql = "SELECT idBarang, jumlahBarang FROM detail_pembelian WHERE idPembelian = ?";
      db.query(findDetailsSql, [id], (err, details) => {
        if (err) {
          return db.rollback(() => callback(err, null));
        }

        if (details.length === 0) {
          const deletePembelianSql = "DELETE FROM pembelian WHERE idPembelian = ?";
          db.query(deletePembelianSql, [id], (err, result) => {
            if (err) {
              return db.rollback(() => callback(err, null));
            }
            db.commit(err => {
              if (err) {
                return db.rollback(() => callback(err, null));
              }
              callback(null, result);
            });
          });
          return; 
        }

        let stockUpdatesCompleted = 0;
        details.forEach(item => {
          const updateStokSql = "UPDATE barang SET stokBarang = stokBarang + ? WHERE idBarang = ?";
          db.query(updateStokSql, [item.jumlahBarang, item.idBarang], (err, updateResult) => {
            if (err) {
              return db.rollback(() => callback(err, null));
            }
            
            stockUpdatesCompleted++;

            if (stockUpdatesCompleted === details.length) {
              const deleteDetailsSql = "DELETE FROM detail_pembelian WHERE idPembelian = ?";
              db.query(deleteDetailsSql, [id], (err, deleteDetailsResult) => {
                if (err) {
                  return db.rollback(() => callback(err, null));
                }

                const deletePembelianSql = "DELETE FROM pembelian WHERE idPembelian = ?";
                db.query(deletePembelianSql, [id], (err, finalResult) => {
                  if (err) {
                    return db.rollback(() => callback(err, null));
                  }

                  db.commit(err => {
                    if (err) {
                      return db.rollback(() => callback(err, null));
                    }
                    callback(null, finalResult);
                  });
                });
              });
            }
          });
        });
      });
    });
  },

    hitungTotalHargaPembelian: (idPembelian, callback) => {
        const query = `
            SELECT SUM(dp.totalHargaBarang) AS total_harga_pembelian
            FROM detail_pembelian dp
            WHERE dp.idPembelian = ?;

            INSERT INTO pembelian (totalHarga) VALUES (total_harga_pembelian);
        `;
        db.query(query, [idPembelian], callback);
    },

    createPesanan: async (pesananData) => {
    const { totalHarga, items, userId } = pesananData;

    if (!items || !items.length) {
      throw new Error('Keranjang tidak boleh kosong.');
    }

    try {
      await db.promise().beginTransaction();

      const idPembelian = await Pembelian.generateNextPembelianId();
      
      const pembelianSql = 'INSERT INTO pembelian (idPembelian, waktuTransaksi, totalHarga, userId, status) VALUES (?, NOW(), ?, ?, ?)';
      await db.promise().query(pembelianSql, [idPembelian, totalHarga, userId, 'pending']);

      for (const item of items) {
        const detailSql = 'INSERT INTO detail_pembelian (idPembelian, idBarang, jumlahBarang, totalHargaBarang) VALUES (?, ?, ?, ?)';
        const detailValues = [idPembelian, item.idBarang, item.jumlahBarang, item.totalHargaBarang];
        await db.promise().query(detailSql, detailValues);
      }

      await db.promise().commit();
      return { message: 'Pesanan berhasil dibuat dan menunggu persetujuan admin.', idPembelian: idPembelian };
    } catch (error) {
      await db.promise().rollback();
      throw error; 
    }
  },

  updateStatusPesanan: async (id, status) => {
    try {
      await db.promise().beginTransaction();

      if (status === 'completed') {
        const [details] = await db.promise().query("SELECT idBarang, jumlahBarang FROM detail_pembelian WHERE idPembelian = ?", [id]);
        
        for(const item of details) {
          const [barangRows] = await db.promise().query("SELECT stokBarang FROM barang WHERE idBarang = ?", [item.idBarang]);
          if (barangRows[0].stokBarang < item.jumlahBarang) {
            throw new Error(`Stok untuk barang ID ${item.idBarang} tidak mencukupi.`);
          }
          await db.promise().query("UPDATE barang SET stokBarang = stokBarang - ? WHERE idBarang = ?", [item.jumlahBarang, item.idBarang]);
        }
      }
      

      const [result] = await db.promise().query("UPDATE pembelian SET status = ? WHERE idPembelian = ?", [status, id]);
      
      await db.promise().commit();
      return result;
    } catch (error) {

      await db.promise().rollback();
      throw error;
    }
  },

};

Pembelian.getPembelianByStatus = async (status) => {
    const sql = `
      SELECT 
        p.idPembelian, 
        p.waktuTransaksi, 
        p.totalHarga, 
        p.status, 
        u.nama as namaUser,
        u.email 
      FROM pembelian p 
      LEFT JOIN users u ON p.userId = u.id 
      WHERE p.status = ? 
      ORDER BY p.waktuTransaksi DESC
    `;
    try {
      const [rows] = await db.promise().query(sql, [status]);
      return rows;
    } catch (error) {
      throw error;
    }
  },

Pembelian.generateNextPembelianId = async () => {
  const [rows] = await db.promise().query(
    "SELECT idPembelian FROM pembelian ORDER BY idPembelian DESC LIMIT 1"
  );

  if (rows.length === 0) {
    return "P-001";
  }

  const lastId = rows[0].idPembelian;
  const lastNumber = parseInt(lastId.split("-")[1]);
  const nextNumber = lastNumber + 1;
  const nextId = `P-${String(nextNumber).padStart(3, "0")}`;

  return nextId;
};

Pembelian.createPembelian = (pembelianData, callback) => {
  const { totalHarga, items } = pembelianData;

  if (!items || items.length === 0) {
    return callback({ message: 'Keranjang tidak boleh kosong.' });
  }

  db.beginTransaction(async (err) => {
    if (err) {
      return callback({ message: "Gagal memulai transaksi" });
    }

    const idPembelian = await Pembelian.generateNextPembelianId();
    if (!idPembelian) {
      return db.rollback(() => callback({ message: 'Gagal membuat ID Pembelian.' }));
    }

    const pembelianSql = 'INSERT INTO pembelian (idPembelian, waktuTransaksi, totalHarga) VALUES (?, NOW(), ?)';
      
      db.query(pembelianSql, [idPembelian, totalHarga], (err, pembelianResult) => {
        if (err) {
          return db.rollback(() => callback({ message: 'Transaksi dibatalkan karena error pembelian.' }));
        }

        let completedTasks = 0;
        const totalTasks = items.length * 2; 

        items.forEach(item => {
          const detailSql = 'INSERT INTO detail_pembelian (idPembelian, idBarang, jumlahBarang, totalHargaBarang) VALUES (?, ?, ?, ?)';
          const detailValues = [idPembelian, item.idBarang, item.jumlahBarang, item.totalHargaBarang];
          
          db.query(detailSql, detailValues, (err, detailResult) => {
            if (err) {
              return db.rollback(() => callback({ message: 'Transaksi dibatalkan karena error detail.' }));
            }
            completedTasks++;

            const updateStokSql = 'UPDATE barang SET stokBarang = stokBarang - ? WHERE idBarang = ?';
            db.query(updateStokSql, [item.jumlahBarang, item.idBarang], (err, updateResult) => {
              if (err) {
                return db.rollback(() => callback({ message: 'Transaksi dibatalkan karena error update stok.' }));
              }
              completedTasks++;

              if (completedTasks === totalTasks) {
                db.commit(err => {
                  if (err) {
                    return db.rollback(() => callback({ message: 'Gagal melakukan commit transaksi.' }));
                  }
                  callback(null, { message: 'Transaksi berhasil disimpan!', idPembelian: idPembelian });
                });
              }
            });
          });
        });
      });
  });
};
module.exports = Pembelian;