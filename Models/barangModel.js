const db = require("../Database/db");
const path = require("path");
const fs = require("fs");

const Barang = {
  getAllBarang: (callback) => {
    db.query("SELECT * FROM barang", callback);
  },

  getBarangById: (id, callback) => {
    db.query("SELECT * FROM barang WHERE idBarang = ?", [id], callback);
  },

  updateBarang: (id, barangData, callback) => {
    if (barangData.gambar) {
      db.query(
        "SELECT gambar FROM barang WHERE idBarang = ?",
        [id],
        (err, result) => {
          if (err) {
            return callback(err, null);
          }

          if (result.length === 0) {
            return callback(new Error("Barang tidak ditemukan"), null);
          }

          const gambarLama = result[0].gambar;

          db.query(
            "UPDATE barang SET ? WHERE idBarang = ?",
            [barangData, id],
            (err, updateResult) => {
              if (err) {
                return callback(err, null);
              }

              if (gambarLama) {
                const pathToImage = path.join(
                  __dirname,
                  "..",
                  "uploads",
                  gambarLama
                );
                fs.unlink(pathToImage, (unlinkErr) => {
                  if (unlinkErr) {
                    console.error("Gagal menghapus gambar lama:", unlinkErr);
                  }
                });
              }
              callback(null, updateResult);
            }
          );
        }
      );
    } else {
      db.query(
        "UPDATE barang SET ? WHERE idBarang = ?",
        [barangData, id],
        callback
      );
    }
  },

  deleteBarang: (id, callback) => {
    db.query("DELETE FROM barang WHERE idBarang = ?", [id], callback);
  },

  cekKetersediaan: (idBarang, jumlahDibutuhkan, callback) => {
    const query = "SELECT stokBarang FROM barang WHERE idBarang = ?";
    db.query(query, [idBarang], (err, results) => {
      if (err) {
        return callback(err);
      }
      if (results.length > 0) {
        const stok = results[0].stokBarang;
        if (stok >= jumlahDibutuhkan) {
          callback(null, true);
        } else {
          callback(null, false);
        }
      } else {
        callback(null, false);
      }
    });
  },

  updateStokBarang: (idBarang, jumlah, callback) => {
    const query = `
        UPDATE barang SET stokBarang = stokBarang - ? WHERE idBarang = ?;

        IF (stokBarang - ? <= 0) THEN
            UPDATE barang SET tersedia = FALSE WHERE idBarang = ?;
        END IF;

        IF (stokBarang - ? > 0) THEN
            UPDATE barang SET tersedia = TRUE WHERE idBarang = ?;
        END IF;
        `;
    db.query(query, [jumlah, idBarang], callback);
  },

  isTersedia: (idBarang, callback) => {
    const query = "SELECT tersedia FROM barang WHERE idBarang = ?";
    db.query(query, [idBarang], callback);
  },

  searchBarang: (keyword, callback) => {
    const query = "SELECT * FROM barang WHERE namaBarang LIKE ?";
    const searchKeyword = `%${keyword}%`;
    db.query(query, [searchKeyword], callback);
  },
};

Barang.generateNextBarangId = async () => {
  const [rows] = await db.promise().query(
    "SELECT idBarang FROM barang ORDER BY idBarang DESC LIMIT 1"
  );

  if (rows.length === 0) {
    return "B-001";
  }

  const lastId = rows[0].idBarang;
  const lastNumber = parseInt(lastId.split("-")[1]);
  const nextNumber = lastNumber + 1;
  const nextId = `B-${String(nextNumber).padStart(3, "0")}`;

  return nextId;
};

Barang.createBarang = async (barangData, callback) => {
  try {
    const newId = await Barang.generateNextBarangId();
    const tersedia = barangData.stokBarang > 0 ? true : false;
    barangData.tersedia = tersedia;
    const dataToInsert = {
      idBarang: newId,
      tersedia: tersedia,
      ...barangData,
    };

    const [result] = await db.promise().query("INSERT INTO barang SET ?", dataToInsert);
    callback(null, result);
  } catch (err) {
    console.error("Error di createBarang model:", err);
    callback(err, null);
  }
};

module.exports = Barang;
