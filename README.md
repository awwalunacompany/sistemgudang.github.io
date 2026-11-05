# Sistem Gudang

Aplikasi manajemen persediaan gudang (stok, transaksi, ekspedisi, opname, laporan) dengan login berbasis peran.
Berjalan sepenuhnya di browser, tanpa server.

## Struktur

```
index.html
assets/
  css/style.css
  js/app.js
  img/gudang.jpg
.nojekyll
```

## Hosting di GitHub Pages

1. Buat repository baru di GitHub, lalu unggah **seluruh isi folder ini** (bukan folder pembungkusnya) ke branch `main`.
2. Buka **Settings → Pages**.
3. Pada **Build and deployment**, pilih **Deploy from a branch**, branch `main`, folder `/ (root)`, lalu **Save**.
4. Tunggu 1-2 menit. Situs tampil di `https://USERNAME.github.io/NAMA-REPO/`.

## Catatan penting

- Data dan akun disimpan di **localStorage browser** masing-masing perangkat. Data tidak tersinkron antar perangkat.
- Akun awal dan sandi sementara ada di file `Daftar_Akun.txt` (tidak termasuk di repo ini; jangan diunggah ke GitHub).
  Setiap akun wajib mengganti sandi saat login pertama.
- Login ini adalah pembatas akses di tampilan, bukan pengamanan server.
