const db = require('../Database/db');

const detailPembelian = {
    getAllDetailPembelian: (callback)=> {
        db.query("SELECT * FROM detail_pembelian", callback);
    },

    getDetailPembelianById: (id, callback) => {
        db.query(`SELECT 
                b.namaBarang,
                b.hargaBarang,
                dp.jumlahBarang,
                dp.totalHargaBarang
            FROM 
                detail_pembelian dp
            JOIN 
                barang b ON dp.idBarang = b.idBarang
            WHERE 
                dp.idPembelian = ?;
        `, [id], callback);
    },

    updateDetailPembelian: (id, detailPembelianData, callback) => {
        db.query("UPDATE detail_pembelian SET ? WHERE id = ?", [detailPembelianData, id], callback);
    },
    
    deleteDetailPembelian: (id, callback) => {
        db.query("DELETE FROM detail_pembelian WHERE id = ?", [id], callback);
    },

    hitungSubTotal: (idDetailPembelian, callback) => {
        const query = `
            SELECT SUM(b.harga * dp.jumlah) AS total_harga_barang
            FROM detail_pembelian dp
            JOIN barang b ON dp.idBarang = b.idBarang
            WHERE dp.idDetailPembelian = ?;

            INSERT INTO detail_pembelian (totalHargaBarang) VALUES (total_harga_barang);
        `;
        db.query(query, [idDetailPembelian], callback);
    }

};

module.exports = detailPembelian;