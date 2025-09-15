const db = require('../Database/db');
const PdfPrinter = require('pdfmake');
const path = require('path');

const fonts = {
  Roboto: {
    normal: 'node_modules/roboto-font/fonts/Roboto/roboto-regular-webfont.ttf',
    bold: 'node_modules/roboto-font/fonts/Roboto/roboto-medium-webfont.ttf',
    italics: 'node_modules/roboto-font/fonts/Roboto/roboto-italic-webfont.ttf',
    bolditalics: 'node_modules/roboto-font/fonts/Roboto/roboto-mediumitalic-webfont.ttf'
  }
};

const LaporanController = {
  getRingkasan: (req, res) => {
    const sqlPemasukan = "SELECT SUM(totalHarga) AS totalPemasukan FROM pembelian";
    const sqlTransaksi = "SELECT COUNT(*) AS jumlahTransaksi FROM pembelian";
    const sqlBarangTerjual = "SELECT SUM(jumlahBarang) AS totalBarangTerjual FROM detail_pembelian";

    let ringkasan = {};

    db.query(sqlPemasukan, (err, pemasukanResult) => {
      if (err) {
        console.error("Error mengambil pemasukan:", err);
        return res.status(500).json({ message: "Gagal mengambil data." });
      }
      ringkasan.totalPemasukan = pemasukanResult[0].totalPemasukan || 0;

      db.query(sqlTransaksi, (err, transaksiResult) => {
        if (err) {
          console.error("Error mengambil transaksi:", err);
          return res.status(500).json({ message: "Gagal mengambil data." });
        }
        ringkasan.jumlahTransaksi = transaksiResult[0].jumlahTransaksi || 0;

        db.query(sqlBarangTerjual, (err, barangResult) => {
          if (err) {
            console.error("Error mengambil barang terjual:", err);
            return res.status(500).json({ message: "Gagal mengambil data." });
          }
          ringkasan.totalBarangTerjual = barangResult[0].totalBarangTerjual || 0;

          res.json(ringkasan);
        });
      });
    });
  },

  getBarangTerlaris: (req, res) => {
    const sql = `
      SELECT b.namaBarang, SUM(dp.jumlahBarang) AS totalTerjual
      FROM detail_pembelian dp
      JOIN barang b ON dp.idBarang = b.idBarang
      GROUP BY b.idBarang, b.namaBarang
      ORDER BY totalTerjual DESC
      LIMIT 5
    `;
    
    db.query(sql, (err, rows) => {
        if (err) {
            console.error("Error mengambil barang terlaris:", err);
            return res.status(500).json({ message: "Gagal mengambil data barang terlaris." });
        }
        res.json(rows);
    });
  },

  generateLaporanPDF: (req, res) => {
    const sql = `
      SELECT p.idPembelian, p.totalHarga, p.status, p.waktuTransaksi, u.nama AS namaUser
      FROM pembelian p
      JOIN users u ON p.userId = u.id
      ORDER BY p.waktuTransaksi DESC
      LIMIT 100
    `;

    db.query(sql, (err, rows) => {
      if (err) {
        console.error("Error mengambil data pembelian:", err);
        return res.status(500).json({ message: "Gagal mengambil data pembelian." });
      }
      const printer = new PdfPrinter(fonts);
      const docDefinition = {
        content: [
          { text: 'Laporan Pembelian Katalog', style: 'header' },
          { text: `Tanggal: ${new Date().toLocaleDateString()}`, style: 'subheader' },
          {
            table: {
              headerRows: 1,
              widths: ['*', '*', '*', '*', '*'],
              body: [
                ['ID Pembelian', 'Nama User', 'Total Harga', 'Status', 'Waktu Transaksi'],
                ...rows.map(row => [
                  row.idPembelian,
                  row.namaUser,
                  `Rp ${row.totalHarga.toLocaleString()}`,
                  row.status,
                  new Date(row.waktuTransaksi).toLocaleString()
                ])
              ]
            }
          }
        ],
        styles: {
          header: { fontSize: 18, bold: true, margin: [0, 0, 0, 10] },
          subheader: { fontSize: 14, margin: [0, 10, 0, 5] },
          tableHeader: { bold: true, fontSize: 13, color: 'black' }
        }
      };
      const pdfDoc = printer.createPdfKitDocument(docDefinition);
      let chunks = [];
      pdfDoc.on('data', chunk => {
        chunks.push(chunk);
      });
      pdfDoc.on('end', () => {
        const result = Buffer.concat(chunks);
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', 'attachment; filename=Laporan-Pembelian-Katalog.pdf');
        res.send(result);
      });
      pdfDoc.end();
    });
  }
};

module.exports = LaporanController;