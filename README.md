# GlassGuard 1.1.0

Aplikasi Android/Google TV setempat, antara muka Bahasa Melayu liquid glass. Pakej: `com.glassguard`. Minimum manifest Android 6 (API 23), memerlukan Android System WebView moden (Chromium 86+); binaan ini diuji pada Google TV Android 14 sahaja. Sasaran API 35.

## Fungsi sebenar

- Imbas pakej pengguna dan sistem (termasuk disabled), base APK dan split APK yang boleh dibaca.
- Semak SHA-256 keseluruhan APK dan entri DEX/library terhadap 78 hash unik yang diterbitkan Google Threat Intelligence Group dalam laporan XCPE. Pemetaan mengekalkan lebih satu label jika hash yang sama mempunyai beberapa komponen.
- Kenal pasti nama pakej XCPE/ABCNexus/dropper sebagai indikator sahaja. Hash yang tidak sepadan bukan bukti selamat.
- Petunjuk BADBOX 2.0: `libanl.so`, kelas `Lcom/hs/app;`, dan beberapa lokasi library firmware. Nama library/kelas sahaja TIDAK mengesahkan malware.
- Petunjuk root daripada beberapa lokasi fail. Tidak meminta akses root atau menjalankan `su`.
- Papar bukti, sumber, batasan, jumlah aplikasi diperiksa, status aktif/disabled dan bacaan RAM sebenar.
- Hapus aplikasi pengguna melalui dialog pengesahan Android. Pakej sistem dibuka dalam tetapan untuk nyahaktif jika firmware membenarkan; aplikasi tidak boleh membuang fail /system.
- Android 14+: buka tetapan untuk pengurusan aplikasi/RAM. Android lebih lama: permintaan tutup background hanya aplikasi pengguna yang dipilih sendiri; launcher, keyboard, accessibility dan sistem dikecualikan. Penutupan mungkin mengganggu notifikasi/VPN/media. Tiada jaminan RAM tertentu dibebaskan.
- Simpan laporan terakhir dalam storan aplikasi peribadi; kongsi JSON melalui Android share sheet jika pengguna memilih. Laporan mengandungi nama pakej/laluan fail.
- Kemas kini sendiri melalui GitHub Releases. Menekan "Check for update" membaca `releases/latest` repo `tivoacc174-afk/GlassGuard` dan membandingkan `versionCode` daripada tag `vMAJOR.MINOR.PATCH`. Muat turun hanya berlaku apabila pengguna menekan butang pasang.

## Kemas kini: apa yang disemak sebelum memasang

Tiada muat turun automatik, tiada pemasangan senyap. Aliran penuh apabila butang ditekan:

1. URL aset mesti `https://github.com/tivoacc174-afk/GlassGuard/releases/download/<tag>/<fail>.apk` — tepat satu segmen tag dan satu fail `.apk`, tanpa query, fragmen, userinfo, port atau `%`-encoding. Repo lain, HTTP, subdomain `github.com.evil.test` dan traversal ditolak (`UpdatePolicy.isAssetUrl`).
2. Ubah hala GitHub ke CDN hanya diterima untuk `release-assets.githubusercontent.com` (`UpdatePolicy.isTransportUrl`); had 5 lompatan dan 64 MiB.
3. `tag_name` mesti `vMAJOR.MINOR.PATCH` dengan setiap bahagian ≤ 2 digit; tag cacat memberi -1, bukan versi.
4. SHA-256 fail yang dimuat turun mesti sama dengan `digest` aset GitHub. Hash hilang atau tidak sepadan membatalkan pemasangan. Nilai hash yang cacat ditolak, bukan dibaiki.
5. `PackageManager.getPackageArchiveInfo` mesti melaporkan pakej `com.glassguard`, `versionCode` yang diumumkan, dan sijil penandatangan yang sama seperti APK yang sedang dipasang.
6. Hanya selepas semua lulus, fail diserahkan kepada `PackageInstaller`. Android masih meminta pengesahan pengguna sendiri; GlassGuard tidak boleh memasang secara senyap.

Kebenaran tambahan: `INTERNET` (hanya untuk semakan/muat turun kemas kini) dan `REQUEST_INSTALL_PACKAGES`. WebView kekal `setBlockNetworkLoads(true)`; semua trafik kemas kini menggunakan `HttpURLConnection` dalam kod native, bukan halaman.

Penting: kunci tandatangan dalam `signing/` mesti kekal sama untuk setiap keluaran. Jika kunci hilang atau bertukar, Android akan menolak kemas kini (tandatangan tidak sepadan) dan pengguna perlu memasang semula secara manual.

## Batas keselamatan

Ini pengimbas indikator terhad, BUKAN pengganti antivirus menyeluruh atau bukti peranti bersih. Tiada pemantauan trafik, pengesahan seluruh firmware, analisis dinamik, pengimbasan data aplikasi lain, atau jaminan mengesan root/backdoor tersembunyi. Signature tidak dikemas kini automatik. Tarikh dan sumber signature perlu disemak semula untuk binaan masa depan.

APK tidak meminta kebenaran INTERNET, accessibility, storage menyeluruh atau root. WebView hanya memuat aset setempat melalui HTTPS origin yang dipintas. Navigasi/permintaan lain disekat. JavaScript bridge hanya pada aset UI yang dibundel. Tiada APK mencurigakan dimuat turun/dijalankan semasa imbasan.

Had bacaan: 64 MiB setiap entri DEX/library dan 256 MiB bagi kandungan DEX/library setiap APK. APK besar/tidak boleh dibaca dilaporkan sebagai imbasan separa. Hash keseluruhan APK dibaca streaming. Pengesanan tidak bermaksud pembasmian firmware.

Jika disyaki firmware backdoor: asingkan peranti daripada akaun/rangkaian sensitif, dapatkan firmware bersih yang disahkan pengeluar atau ganti peranti. Factory reset/uninstall mungkin tidak membuang salinan /system atau /oem. Jangan flash imej daripada sumber rawak.

## Bina semula pada komputer ini

    python build.py

`build.py` menjalankan semua ujian dahulu (harness JVM scanner, 4 peringkat polisi pengemas kini, 12 ujian UI Node, 4 ujian kontrak native) kemudian membina dan menandatangani APK. Jika mana-mana ujian gagal, binaan berhenti.

Alat binaan dalam `tools/`: Microsoft OpenJDK 17, Android build-tools 35.0.0, platform API 35 dan platform-tools daripada Google. Build dilakukan terus dengan javac, aapt2, D8, zipalign dan apksigner; tiada Gradle/dependensi runtime.

Kunci tandatangan binaan setempat dalam `signing/` mesti disimpan secara peribadi untuk kemas kini APK. Ia bukan sijil Play Store. Jangan terbitkan folder signing.

## Pasang

    tools/platform-tools/adb.exe connect 192.168.0.99:5555
    tools/platform-tools/adb.exe -s 192.168.0.99:5555 install -r dist/GlassGuard-1.0.0.apk
    tools/platform-tools/adb.exe -s 192.168.0.99:5555 shell am start -n com.glassguard/.MainActivity

Luluskan USB debugging pada peranti. Selepas selesai, matikan network/USB debugging jika tidak digunakan; jangan dedahkan port ADB ke internet.

## Sumber indikator

- https://cloud.google.com/blog/topics/threat-intelligence/shutting-the-door-on-the-xcpe-botnet
- https://www.humansecurity.com/learn/blog/satori-threat-intelligence-disruption-badbox-2-0/

`research/xcpe.txt` ialah salinan teks sumber semasa binaan. `build_signatures.py` mengekstrak hash 64-hex daripada jadual sumber; token 32-hex dalam lajur SHA256 ditolak, bukan dipanjangkan/dibaiki. `assets/sources.json` menyimpan provenance.
