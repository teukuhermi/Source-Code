<?php
if (!defined('INDEX_AUTH')) {
    die('can not access this file directly');
}

use SLiMS\DB;

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Buat CSRF Token jika belum ada
if (empty($_SESSION['csrf_daftar_mandiri'])) {
    $_SESSION['csrf_daftar_mandiri'] = bin2hex(random_bytes(32));
}

$db = DB::getInstance();
$pesan = '';
$tipe_pesan = '';

// Ambil daftar Tipe Keanggotaan
$stmtType = $db->query("SELECT member_type_id, member_type_name FROM mst_member_type");
$memberTypes = $stmtType->fetchAll(PDO::FETCH_ASSOC);

// Fungsi pembantu untuk mengambil opsi Dropdown dari Ruas Tambahan (mst_custom_field)
function getCustomFieldOptions($db, $labelName) {
    $stmt = $db->prepare("SELECT data FROM mst_custom_field WHERE primary_table = 'member' AND LOWER(label) = LOWER(:lbl) LIMIT 1");
    $stmt->execute([':lbl' => $labelName]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$row || empty($row['data'])) {
        return [];
    }

    $raw = json_decode($row['data'], true);
    if (!is_array($raw)) {
        $raw = @unserialize($row['data']);
    }
    if (!is_array($raw)) {
        return [];
    }

    $options = [];
    foreach ($raw as $key => $item) {
        if (is_array($item)) {
            // Format bawaan SLiMS: [0 => '0', 1 => 'FAKULTAS EKONOMI']
            $kode = $item[0] ?? $key;
            $teks = $item[1] ?? ($item[0] ?? '');
        } else {
            // Format key => value
            $kode = $key;
            $teks = $item;
        }
        if ($teks !== '') {
            $options[] = [
                'kode' => (string)$kode,
                'teks' => (string)$teks
            ];
        }
    }
    return $options;
}

$opsiFakultas = getCustomFieldOptions($db, 'Fakultas');
$opsiJurusan  = getCustomFieldOptions($db, 'Jurusan');

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['submit_daftar'])) {

    // 1. Validasi CSRF Token
    $token = $_POST['csrf_token'] ?? '';
    if (!hash_equals($_SESSION['csrf_daftar_mandiri'], $token)) {
        die('Permintaan tidak valid (CSRF Token Mismatch). Silakan muat ulang halaman.');
    }

    // 2. Proteksi Honeypot (Anti-Bot)
    if (!empty($_POST['website_url'])) {
        die('Aktivitas mencurigakan terdeteksi.');
    }

    // 3. Rate Limiting Sederhana (Jeda 30 detik antar pendaftaran)
    if (isset($_SESSION['last_reg_time']) && (time() - $_SESSION['last_reg_time']) < 30) {
        $pesan = 'Terlalu banyak percobaan. Silakan tunggu 30 detik sebelum mengirim ulang.';
        $tipe_pesan = 'warning';
    } else {
        // Sanitasi & Validasi Ketat Input
        $member_id      = preg_replace('/[^a-zA-Z0-9\-]/', '', trim($_POST['member_id'] ?? ''));
        $member_name    = trim(strip_tags($_POST['member_name'] ?? ''));
        $birth_date     = trim($_POST['birth_date'] ?? '');
        $gender         = in_array((int)($_POST['gender'] ?? 1), [0, 1], true) ? (int)$_POST['gender'] : 1;
        $member_type_id = (int)($_POST['member_type_id'] ?? 1);
        $member_email   = filter_var(trim($_POST['member_email'] ?? ''), FILTER_VALIDATE_EMAIL);
        $member_phone   = preg_replace('/[^0-9\+]/', '', trim($_POST['member_phone'] ?? ''));
        $member_address = trim(strip_tags($_POST['member_address'] ?? ''));
        $fakultas       = trim(strip_tags($_POST['fakultas'] ?? ''));
        $jurusan        = trim(strip_tags($_POST['jurusan'] ?? ''));
        $inst_name      = trim(strip_tags($_POST['inst_name'] ?? ''));
        $password       = $_POST['mpasswd'] ?? '';

        // Validasi Tanggal Lahir Wajib (Format YYYY-MM-DD)
        $valid_birth_date = false;
        if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $birth_date)) {
            $d = DateTime::createFromFormat('Y-m-d', $birth_date);
            if ($d && $d->format('Y-m-d') === $birth_date && $birth_date <= date('Y-m-d') && $birth_date >= '1920-01-01') {
                $valid_birth_date = true;
            }
        }

        // Validasi Panjang & Karakter Password
        if (strlen($password) < 8 || strlen($password) > 72 || !preg_match('/[A-Z]/', $password) || !preg_match('/[a-z]/', $password) || !preg_match('/[0-9]/', $password)) {
            $pesan = 'Password harus 8-72 karakter serta mengandung huruf besar, huruf kecil, dan angka.';
            $tipe_pesan = 'danger';
        } elseif (!$valid_birth_date) {
            $pesan = 'Tanggal lahir wajib diisi dengan format tanggal yang benar.';
            $tipe_pesan = 'danger';
        } elseif (empty($member_id) || strlen($member_id) > 20 || empty($member_name) || strlen($member_name) > 100 || !$member_email) {
            $pesan = 'Pastikan NIM/ID (maks 20 karakter), Nama Lengkap, dan format Email sudah benar.';
            $tipe_pesan = 'danger';
        } elseif ((!empty($opsiFakultas) && empty($fakultas)) || (!empty($opsiJurusan) && empty($jurusan))) {
            $pesan = 'Silakan pilih Fakultas dan Jurusan Anda.';
            $tipe_pesan = 'danger';
        } else {
            // Cek Duplikasi di Tabel Anggota Aktif (`member`) MAUPUN Tabel Antrean (`member_pending`)
            $cekAktif = $db->prepare("SELECT member_id FROM member WHERE member_id = :mid LIMIT 1");
            $cekAktif->execute([':mid' => $member_id]);

            $cekPending = $db->prepare("SELECT member_id FROM member_pending WHERE member_id = :mid LIMIT 1");
            $cekPending->execute([':mid' => $member_id]);

            if ($cekAktif->rowCount() > 0) {
                $pesan = 'NIM / ID Anggota sudah terdaftar aktif di sistem perpustakaan.';
                $tipe_pesan = 'warning';
            } elseif ($cekPending->rowCount() > 0) {
                $pesan = 'Pendaftaran dengan NIM / ID tersebut sudah masuk dan sedang menunggu verifikasi pustakawan.';
                $tipe_pesan = 'warning';
            } else {
                // 4. PROSES KEAMANAN UNGGAH FOTO (RE-ENCODING GAMBAR VIA GD LIBRARY)
                $nama_file_foto = null;
                if (isset($_FILES['member_image']) && $_FILES['member_image']['error'] !== UPLOAD_ERR_NO_FILE) {
                    $file = $_FILES['member_image'];

                    if ($file['error'] !== UPLOAD_ERR_OK) {
                        $pesan = 'Gagal mengunggah foto. Kode error: ' . $file['error'];
                        $tipe_pesan = 'danger';
                    } elseif ($file['size'] > 2 * 1024 * 1024) {
                        $pesan = 'Ukuran foto maksimal adalah 2 MB.';
                        $tipe_pesan = 'danger';
                    } else {
                        $img_info = @getimagesize($file['tmp_name']);
                        $finfo    = new finfo(FILEINFO_MIME_TYPE);
                        $mime     = $finfo->file($file['tmp_name']);

                        $allowed_mimes = ['image/jpeg', 'image/png'];
                        if ($img_info === false || !in_array($mime, $allowed_mimes, true)) {
                            $pesan = 'File ditolak! Pastikan file adalah gambar JPG atau PNG asli.';
                            $tipe_pesan = 'danger';
                        } else {
                            $random_name = 'mbr_' . bin2hex(random_bytes(16));

                            if ($mime === 'image/jpeg') {
                                $src_img = @imagecreatefromjpeg($file['tmp_name']);
                                if ($src_img) {
                                    $nama_file_foto = $random_name . '.jpg';
                                    $tujuan = IMGBS . 'persons/' . $nama_file_foto;
                                    imagejpeg($src_img, $tujuan, 85);
                                    imagedestroy($src_img);
                                }
                            } elseif ($mime === 'image/png') {
                                $src_img = @imagecreatefrompng($file['tmp_name']);
                                if ($src_img) {
                                    $nama_file_foto = $random_name . '.png';
                                    $tujuan = IMGBS . 'persons/' . $nama_file_foto;
                                    imagepng($src_img, $tujuan, 6);
                                    imagedestroy($src_img);
                                }
                            }

                            if (!$nama_file_foto || !file_exists($tujuan)) {
                                $pesan = 'File gambar rusak atau tidak dapat diproses oleh server.';
                                $tipe_pesan = 'danger';
                            } else {
                                @chmod($tujuan, 0644);
                            }
                        }
                    }
                }

                // 5. Simpan ke tabel antrean sementara `member_pending`
                if ($tipe_pesan !== 'danger') {
                    $hashed_pass = password_hash($password, PASSWORD_BCRYPT);
                  

                    $sql = "INSERT INTO member_pending (
                                member_id, member_name, birth_date, gender, member_type_id, 
                                member_email, member_phone, member_address, inst_name, 
                                fakultas, jurusan, member_image, mpasswd, input_date
                            ) VALUES (
                                :mid, :mname, :bdate, :gender, :mtype, 
                                :email, :phone, :addr, :inst, 
                                :fak, :jur, :img, :pass, NOW()
                            )";

                    $insert = $db->prepare($sql);
                    $berhasil = $insert->execute([
                        ':mid'    => $member_id,
                        ':mname'  => $member_name,
                        ':bdate'  => $birth_date,
                        ':gender' => $gender,
                        ':mtype'  => $member_type_id,
                        ':email'  => $member_email,
                        ':phone'  => $member_phone,
                        ':addr'   => $member_address,
                        ':inst'   => $inst_name,
                        ':fak'    => $fakultas,
                        ':jur'    => $jurusan,
                        ':img'    => $nama_file_foto,
                        ':pass'   => $hashed_pass
                    ]);

                    if ($berhasil) {
                        $_SESSION['last_reg_time'] = time();
                        $_SESSION['csrf_daftar_mandiri'] = bin2hex(random_bytes(32));
                        $pesan = 'Pendaftaran berhasil dikirim! Data Anda sedang menunggu persetujuan pustakawan.';
                        $tipe_pesan = 'success';
                    } else {
                        $pesan = 'Gagal menyimpan data antrean pendaftaran.';
                        $tipe_pesan = 'danger';
                    }
                }
            }
        }
    }
}
?>

<style>
<?php if (isset($_GET['embed']) && $_GET['embed'] == '1'): ?>
<style>
    header, nav, footer, .s-search, .vegas-container, #header, #footer {
        display: none !important;
    }
    body { background: transparent !important; }
</style>
<?php endif; ?>
    .reg-wrapper {
        max-width: 820px;
        margin: 2rem auto;
        padding: 0 15px;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    }
    .reg-card {
        background: #ffffff;
        border-radius: 16px;
        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.07);
        border: 1px solid #eef2f6;
        overflow: hidden;
    }
    .reg-header {
        background: linear-gradient(135deg, #1e3a8a 0%, #2563eb 100%);
        color: #ffffff;
        padding: 2rem 2rem 1.75rem;
        text-align: center;
    }
    .reg-header h3 {
        margin: 0 0 0.4rem;
        font-weight: 700;
        font-size: 1.5rem;
        letter-spacing: -0.02em;
    }
    .reg-header p {
        margin: 0;
        opacity: 0.9;
        font-size: 0.95rem;
    }
    .reg-body {
        padding: 2rem;
    }
    .reg-section-title {
        font-size: 0.85rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        color: #2563eb;
        margin-bottom: 1.1rem;
        padding-bottom: 0.5rem;
        border-bottom: 1px solid #e2e8f0;
        display: flex;
        align-items: center;
        gap: 8px;
    }
    .reg-label {
        font-weight: 600;
        font-size: 0.9rem;
        color: #334155;
        margin-bottom: 0.4rem;
        display: block;
    }
    .reg-input {
        width: 100%;
        padding: 0.68rem 0.95rem;
        font-size: 0.95rem;
        color: #1e293b;
        background-color: #f8fafc;
        border: 1.5px solid #cbd5e1;
        border-radius: 10px;
        transition: all 0.2s ease;
        box-sizing: border-box;
    }
    .reg-input:focus {
        background-color: #ffffff;
        border-color: #2563eb;
        outline: none;
        box-shadow: 0 0 0 4px rgba(37, 99, 235, 0.12);
    }
    .reg-group {
        margin-bottom: 1.25rem;
    }
    .pass-wrapper {
        position: relative;
        display: flex;
        align-items: center;
    }
    .pass-wrapper .reg-input {
        padding-right: 45px;
    }
    .pass-toggle-btn {
        position: absolute;
        right: 12px;
        background: none;
        border: none;
        color: #64748b;
        cursor: pointer;
        padding: 4px;
        font-size: 0.85rem;
        font-weight: 600;
    }
    .pass-toggle-btn:hover {
        color: #1e293b;
    }
    .upload-box {
        border: 2px dashed #cbd5e1;
        border-radius: 12px;
        padding: 1.25rem;
        text-align: center;
        background: #f8fafc;
        cursor: pointer;
        transition: all 0.2s ease;
        position: relative;
    }
    .upload-box:hover {
        border-color: #2563eb;
        background: #eff6ff;
    }
    .upload-preview {
        width: 84px;
        height: 84px;
        border-radius: 50%;
        object-fit: cover;
        margin: 0 auto 0.75rem;
        display: none;
        border: 3px solid #2563eb;
        box-shadow: 0 4px 10px rgba(0,0,0,0.1);
    }
    .reg-btn-submit {
        width: 100%;
        padding: 0.9rem 1.5rem;
        font-size: 1rem;
        font-weight: 700;
        color: #ffffff;
        background: linear-gradient(135deg, #1e3a8a 0%, #2563eb 100%);
        border: none;
        border-radius: 10px;
        cursor: pointer;
        transition: transform 0.15s ease, box-shadow 0.15s ease;
        margin-top: 0.5rem;
    }
    .reg-btn-submit:hover {
        transform: translateY(-1px);
        box-shadow: 0 8px 20px rgba(37, 99, 235, 0.28);
    }
    .reg-btn-submit:active {
        transform: translateY(0);
    }
    .reg-alert {
        padding: 1rem 1.25rem;
        border-radius: 10px;
        margin-bottom: 1.5rem;
        font-size: 0.95rem;
        font-weight: 500;
    }
    .reg-alert-success { background: #dcfce7; color: #166534; border: 1px solid #bbf7d0; }
    .reg-alert-danger  { background: #fee2e2; color: #991b1b; border: 1px solid #fecaca; }
    .reg-alert-warning { background: #fef3c7; color: #92400e; border: 1px solid #fde68a; }
/* Sembunyikan judul bawaan OPAC ("daftar_mandiri") di atas form */
    .result-search > h2,
    #main-content > h2,
    .container > h2:first-child {
        display: none !important;
    }
	
    @media (max-width: 767px) {
        .reg-wrapper {
            margin: 1rem auto;
            padding: 0 10px;
        }
        .reg-header {
            padding: 1.5rem 1.25rem;
        }
        .reg-header h3 {
            font-size: 1.25rem;
        }
        .reg-body {
            padding: 1.25rem;
        }
        .reg-input {
            font-size: 16px;
            padding: 0.75rem 0.9rem;
        }
    }
</style>

<div class="reg-wrapper">
    <div class="reg-card">
        <div class="reg-header">
            <h3>Pendaftaran Anggota Perpustakaan</h3>
            <p>Lengkapi data diri di bawah ini untuk membuat akun keanggotaan mandiri</p>
        </div>

        <div class="reg-body">
            <?php if ($pesan): ?>
                <div class="reg-alert reg-alert-<?= htmlspecialchars($tipe_pesan, ENT_QUOTES, 'UTF-8') ?>">
                    <?= htmlspecialchars($pesan, ENT_QUOTES, 'UTF-8') ?>
                </div>
            <?php endif; ?>

            <form method="POST" action="index.php?p=daftar-mandiri" enctype="multipart/form-data" autocomplete="off">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_daftar_mandiri'], ENT_QUOTES, 'UTF-8') ?>">
                
                <!-- Honeypot Anti-Bot -->
                <div style="display:none;" aria-hidden="true">
                    <input type="text" name="website_url" tabindex="-1" value="">
                </div>

                <!-- Bagian 1: Identitas -->
                <div class="reg-section-title">1. Identitas Pemustaka</div>
                <div class="row">
                    <div class="col-12 col-md-6 reg-group">
                        <label class="reg-label">NIM / NIP / NIK <span class="text-danger">*</span></label>
                        <input type="text" name="member_id" class="reg-input" placeholder="Contoh: 230590101001" maxlength="20" pattern="[a-zA-Z0-9\-]+" title="Hanya huruf, angka, dan tanda hubung" required>
                    </div>
                    <div class="col-12 col-md-6 reg-group">
                        <label class="reg-label">Nama Lengkap (Sesuai KTM/KTP) <span class="text-danger">*</span></label>
                        <input type="text" name="member_name" class="reg-input" placeholder="Masukkan nama lengkap" maxlength="100" required>
                    </div>
                </div>

                <div class="row">
                    <div class="col-12 col-md-4 reg-group">
                        <label class="reg-label">Tanggal Lahir <span class="text-danger">*</span></label>
                        <input type="date" name="birth_date" class="reg-input" min="1920-01-01" max="<?= date('Y-m-d') ?>" required>
                    </div>
                    <div class="col-12 col-md-4 reg-group">
                        <label class="reg-label">Jenis Kelamin</label>
                        <select name="gender" class="reg-input">
                            <option value="1">Laki-laki</option>
                            <option value="0">Perempuan</option>
                        </select>
                    </div>
                    <div class="col-12 col-md-4 reg-group">
                        <label class="reg-label">Tipe Keanggotaan</label>
                        <select name="member_type_id" class="reg-input">
                            <?php foreach ($memberTypes as $type): ?>
                                <option value="<?= (int)$type['member_type_id'] ?>">
                                    <?= htmlspecialchars($type['member_type_name'], ENT_QUOTES, 'UTF-8') ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                </div>

                <!-- Bagian 2: Akademik & Kontak -->
                <div class="reg-section-title mt-2">2. Akademik & Kontak</div>
                <div class="row">
                    <div class="col-12 col-md-6 reg-group">
                        <label class="reg-label">Fakultas <span class="text-danger">*</span></label>
                        <select name="fakultas" class="reg-input" <?= !empty($opsiFakultas) ? 'required' : '' ?>>
                            <option value="">-- Pilih Fakultas --</option>
                            <?php foreach ($opsiFakultas as $opt): ?>
                                <option value="<?= htmlspecialchars($opt['teks'], ENT_QUOTES, 'UTF-8') ?>">
                                    <?= htmlspecialchars($opt['teks'], ENT_QUOTES, 'UTF-8') ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>

                    <div class="col-12 col-md-6 reg-group">
                        <label class="reg-label">Jurusan / Program Studi <span class="text-danger">*</span></label>
                        <select name="jurusan" class="reg-input" <?= !empty($opsiJurusan) ? 'required' : '' ?>>
                            <option value="">-- Pilih Jurusan --</option>
                            <?php foreach ($opsiJurusan as $opt): ?>
                                <option value="<?= htmlspecialchars($opt['teks'], ENT_QUOTES, 'UTF-8') ?>">
                                    <?= htmlspecialchars($opt['teks'], ENT_QUOTES, 'UTF-8') ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                </div>

                <div class="row">
                    <div class="col-12 col-md-6 reg-group">
                        <label class="reg-label">Email Aktif <span class="text-danger">*</span></label>
                        <input type="email" name="member_email" class="reg-input" placeholder="nama@email.com" maxlength="100" required>
                    </div>
                    <div class="col-12 col-md-6 reg-group">
                        <label class="reg-label">Nomor HP / WhatsApp</label>
                        <input type="tel" name="member_phone" class="reg-input" placeholder="08xxxxxxxxxx" maxlength="20">
                    </div>
                </div>

                <div class="reg-group">
                    <label class="reg-label">Instansi / Unit Kerja Tambahan (Opsional)</label>
                    <input type="text" name="inst_name" class="reg-input" placeholder="Kosongkan jika sama dengan Fakultas & Jurusan di atas" maxlength="100">
                </div>

                <div class="reg-group">
                    <label class="reg-label">Alamat Domisili</label>
                    <textarea name="member_address" class="reg-input" rows="2" placeholder="Masukkan alamat lengkap tempat tinggal saat ini" maxlength="255"></textarea>
                </div>

                <!-- Bagian 3: Keamanan Akun & Pas Foto -->
                <div class="reg-section-title mt-2">3. Keamanan Akun & Pas Foto</div>
                <div class="row">
                    <div class="col-12 col-md-6 reg-group">
                        <label class="reg-label">Buat Password OPAC <span class="text-danger">*</span></label>
                        <div class="pass-wrapper">
                            <input type="password" id="mpasswd" name="mpasswd" class="reg-input" placeholder="Minimal 8 karakter" minlength="8" maxlength="72" required>
                            <button type="button" class="pass-toggle-btn" onclick="togglePass()">Lihat</button>
                        </div>
                        <small id="passHint" style="display:block; margin-top:6px; color:#64748b; font-size:0.8rem;">
                            Wajib kombinasi huruf besar, huruf kecil, dan angka.
                        </small>
                    </div>

                    <div class="col-12 col-md-6 reg-group">
                        <label class="reg-label">Pas Foto Resmi (JPG/PNG, Maks. 2 MB)</label>
                        <div class="upload-box" onclick="document.getElementById('member_image').click()">
                            <img id="fotoPreview" class="upload-preview" alt="Pratinjau Foto">
                            <div id="uploadText">
                                <span style="display:block; font-weight:600; color:#2563eb; font-size:0.9rem;">Pilih atau Ambil Foto</span>
                                <span style="font-size:0.8rem; color:#64748b;">Format JPG atau PNG (Maks. 2 MB)</span>
                            </div>
                            <input type="file" id="member_image" name="member_image" accept="image/jpeg,image/png" style="display:none;" onchange="previewImage(this)">
                        </div>
                    </div>
                </div>

                <button type="submit" name="submit_daftar" class="reg-btn-submit">
                    Kirim Pendaftaran Mandiri
                </button>
            </form>
        </div>
    </div>
</div>

<script>
function togglePass() {
    const input = document.getElementById('mpasswd');
    const btn = document.querySelector('.pass-toggle-btn');
    if (input.type === 'password') {
        input.type = 'text';
        btn.textContent = 'Sembunyi';
    } else {
        input.type = 'password';
        btn.textContent = 'Lihat';
    }
}

document.getElementById('mpasswd').addEventListener('input', function() {
    const val = this.value;
    const hint = document.getElementById('passHint');
    const valid = val.length >= 8 && /[A-Z]/.test(val) && /[a-z]/.test(val) && /[0-9]/.test(val);
    if (val.length === 0) {
        hint.style.color = '#64748b';
        hint.textContent = 'Wajib kombinasi huruf besar, huruf kecil, dan angka.';
    } else if (valid) {
        hint.style.color = '#16a34a';
        hint.textContent = '✓ Password sudah memenuhi syarat keamanan.';
    } else {
        hint.style.color = '#dc2626';
        hint.textContent = 'Belum memenuhi syarat: min. 8 karakter, huruf besar, kecil, & angka.';
    }
});

function previewImage(input) {
    const preview = document.getElementById('fotoPreview');
    const text = document.getElementById('uploadText');
    if (input.files && input.files[0]) {
        const file = input.files[0];
        if (file.size > 2 * 1024 * 1024) {
            alert('Ukuran foto terlalu besar! Maksimal adalah 2 MB.');
            input.value = '';
            preview.style.display = 'none';
            text.style.display = 'block';
            return;
        }
        const reader = new FileReader();
        reader.onload = function(e) {
            preview.src = e.target.result;
            preview.style.display = 'block';
            text.innerHTML = '<span style="font-size:0.82rem; color:#2563eb; font-weight:600;">Ketuk untuk mengganti foto</span>';
        };
        reader.readAsDataURL(file);
    }
}
</script>