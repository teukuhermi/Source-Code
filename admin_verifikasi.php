<?php
if (!defined('INDEX_AUTH')) {
    define('INDEX_AUTH', '1');
}

if (!defined('SB')) {
    require_once __DIR__ . '/../../sysconfig.inc.php';
}
require_once SB . 'admin/default/session.inc.php';
require_once SB . 'admin/default/session_check.inc.php';

$can_read  = utility::havePrivilege('membership', 'r');
$can_write = utility::havePrivilege('membership', 'w');

if (!$can_read && !$can_write) {
    die('<div class="alert alert-danger">Anda tidak memiliki hak akses ke modul Keanggotaan.</div>');
}

use SLiMS\DB;

if (empty($_SESSION['csrf_admin_verif'])) {
    $_SESSION['csrf_admin_verif'] = bin2hex(random_bytes(32));
}

$db = DB::getInstance();

// Dapatkan URL endpoint plugin saat ini agar POST AJAX selalu mengarah tepat ke file ini
$plugin_url = $_SERVER['PHP_SELF'] . (!empty($_SERVER['QUERY_STRING']) ? '?' . $_SERVER['QUERY_STRING'] : '');

// Ambil daftar Tipe Keanggotaan & Opsi Ruas Tambahan untuk Form Edit
$memberTypes = $db->query("SELECT member_type_id, member_type_name FROM mst_member_type")->fetchAll(PDO::FETCH_ASSOC);

function getAdminCustomOptions($db, $labelName) {
    $stmt = $db->prepare("SELECT data FROM mst_custom_field WHERE primary_table = 'member' AND LOWER(label) = LOWER(:lbl) LIMIT 1");
    $stmt->execute([':lbl' => $labelName]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$row || empty($row['data'])) return [];

    $raw = json_decode($row['data'], true);
    if (!is_array($raw)) $raw = @unserialize($row['data']);
    if (!is_array($raw)) return [];

    $options = [];
    foreach ($raw as $key => $item) {
        $teks = is_array($item) ? ($item[1] ?? ($item[0] ?? '')) : $item;
        if ($teks !== '') $options[] = (string)$teks;
    }
    return $options;
}

$opsiFakultas = getAdminCustomOptions($db, 'Fakultas');
$opsiJurusan  = getAdminCustomOptions($db, 'Jurusan');

$notif_html = '';

// Proses Aksi (Edit, Setujui, atau Tolak)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['aksi_verif'], $_POST['pending_id'])) {
    if (!$can_write) {
        die('<div class="alert alert-danger">Anda tidak memiliki izin mengubah data.</div>');
    }

    $token = $_POST['csrf_token'] ?? '';
    if (!hash_equals($_SESSION['csrf_admin_verif'], $token)) {
        die('<div class="alert alert-danger">Token keamanan tidak valid. Silakan muat ulang halaman.</div>');
    }

    $pid  = (int)$_POST['pending_id'];
    $aksi = $_POST['aksi_verif'];

    // 1. AKSI SIMPAN PERUBAHAN (EDIT DATA ANTREAN)
    if ($aksi === 'edit_save') {
        $new_mid     = preg_replace('/[^a-zA-Z0-9\-]/', '', trim($_POST['member_id'] ?? ''));
        $new_name    = trim(strip_tags($_POST['member_name'] ?? ''));
        $new_bdate   = trim($_POST['birth_date'] ?? '');
        $new_gender  = in_array((int)($_POST['gender'] ?? 1), [0, 1], true) ? (int)$_POST['gender'] : 1;
        $new_mtype   = (int)($_POST['member_type_id'] ?? 1);
        $new_fak     = trim(strip_tags($_POST['fakultas'] ?? ''));
        $new_jur     = trim(strip_tags($_POST['jurusan'] ?? ''));
        $new_email   = filter_var(trim($_POST['member_email'] ?? ''), FILTER_VALIDATE_EMAIL);
        $new_phone   = preg_replace('/[^0-9\+]/', '', trim($_POST['member_phone'] ?? ''));
        $new_address = trim(strip_tags($_POST['member_address'] ?? ''));
        $new_inst    = trim(strip_tags($_POST['inst_name'] ?? ''));

        if (empty($new_mid) || empty($new_name) || empty($new_bdate) || !$new_email) {
            $notif_html = '<div class="v-alert v-alert-danger"><strong>Gagal memperbarui:</strong> ID/NIM, Nama Lengkap, Tanggal Lahir, dan Email wajib valid.</div>';
        } else {
            $cek1 = $db->prepare("SELECT member_id FROM member WHERE member_id = :mid LIMIT 1");
            $cek1->execute([':mid' => $new_mid]);
            $cek2 = $db->prepare("SELECT id FROM member_pending WHERE member_id = :mid AND id != :pid LIMIT 1");
            $cek2->execute([':mid' => $new_mid, ':pid' => $pid]);

            if ($cek1->rowCount() > 0 || $cek2->rowCount() > 0) {
                $notif_html = '<div class="v-alert v-alert-warning">ID / NIM <strong>' . htmlspecialchars($new_mid, ENT_QUOTES, 'UTF-8') . '</strong> sudah digunakan oleh anggota lain.</div>';
            } else {
                $stmtUpd = $db->prepare("
                    UPDATE member_pending SET 
                        member_id = :mid,
                        member_name = :mname,
                        birth_date = :bdate,
                        gender = :gender,
                        member_type_id = :mtype,
                        fakultas = :fak,
                        jurusan = :jur,
                        inst_name = :inst,
                        member_email = :email,
                        member_phone = :phone,
                        member_address = :addr
                    WHERE id = :pid
                ");
                $stmtUpd->execute([
                    ':mid'    => $new_mid,
                    ':mname'  => $new_name,
                    ':bdate'  => $new_bdate,
                    ':gender' => $new_gender,
                    ':mtype'  => $new_mtype,
                    ':fak'    => $new_fak,
                    ':jur'    => $new_jur,
                    ':inst'   => $new_inst,
                    ':email'  => $new_email,
                    ':phone'  => $new_phone,
                    ':addr'   => $new_address,
                    ':pid'    => $pid
                ]);
                $notif_html = '<div class="v-alert v-alert-info">Data antrean untuk <strong>' . htmlspecialchars($new_name, ENT_QUOTES, 'UTF-8') . '</strong> berhasil diperbarui!</div>';
            }
        }
    }

    // 2. AKSI SETUJUI ATAU TOLAK
    $stmtGet = $db->prepare("
        SELECT p.*, t.member_periode 
        FROM member_pending p 
        LEFT JOIN mst_member_type t ON p.member_type_id = t.member_type_id 
        WHERE p.id = :pid LIMIT 1
    ");
    $stmtGet->execute([':pid' => $pid]);
    $data = $stmtGet->fetch(PDO::FETCH_ASSOC);

    if ($data) {
        if ($aksi === 'approve') {
            try {
                $db->beginTransaction();

                $periode       = (int)($data['member_periode'] ?? 365);
                $register_date = date('Y-m-d');
                $expire_date   = date('Y-m-d', strtotime("+$periode days"));

                $sqlInsert = "INSERT INTO member (
                                member_id, member_name, birth_date, gender, member_type_id, 
                                member_email, member_phone, member_address, inst_name, 
                                member_image, mpasswd, register_date, expire_date, 
                                is_pending, input_date, last_update
                              ) VALUES (
                                :mid, :mname, :bdate, :gender, :mtype, 
                                :email, :phone, :addr, :inst, 
                                :img, :pass, :rdate, :edate, 
                                0, NOW(), NOW()
                              )";

                $stmtIns = $db->prepare($sqlInsert);
                $stmtIns->execute([
                    ':mid'    => $data['member_id'],
                    ':mname'  => $data['member_name'],
                    ':bdate'  => $data['birth_date'],
                    ':gender' => $data['gender'],
                    ':mtype'  => $data['member_type_id'],
                    ':email'  => $data['member_email'],
                    ':phone'  => $data['member_phone'],
                    ':addr'   => $data['member_address'],
                    ':inst'   => $data['inst_name'],
                    ':img'    => $data['member_image'],
                    ':pass'   => $data['mpasswd'],
                    ':rdate'  => $register_date,
                    ':edate'  => $expire_date
                ]);

                $getCustomIndex = function($label, $selectedText) use ($db) {
                    if (empty($selectedText)) return '0';
                    $stmt = $db->prepare("SELECT data FROM mst_custom_field WHERE primary_table = 'member' AND LOWER(label) = LOWER(:lbl) LIMIT 1");
                    $stmt->execute([':lbl' => $label]);
                    $row = $stmt->fetch(PDO::FETCH_ASSOC);
                    if (!$row || empty($row['data'])) return '0';

                    $raw = json_decode($row['data'], true);
                    if (!is_array($raw)) $raw = @unserialize($row['data']);
                    if (!is_array($raw)) return '0';

                    foreach ($raw as $key => $item) {
                        $kode = is_array($item) ? (string)($item[0] ?? $key) : (string)$key;
                        $teks = is_array($item) ? (string)($item[1] ?? ($item[0] ?? '')) : (string)$item;
                        if (strcasecmp(trim($teks), trim($selectedText)) === 0) {
                            return $kode;
                        }
                    }
                    return '0';
                };

                $kodeFakultas = $getCustomIndex('Fakultas', $data['fakultas'] ?? '');
                $kodeJurusan  = $getCustomIndex('Jurusan', $data['jurusan'] ?? '');

                $sqlCustom = "REPLACE INTO member_custom (`member_id`, `cf_66e4d`, `cf_67abf`) 
                              VALUES (:mid, :fak, :jur)";
                $stmtCust = $db->prepare($sqlCustom);
                $stmtCust->execute([
                    ':mid' => $data['member_id'],
                    ':fak' => $kodeFakultas,
                    ':jur' => $kodeJurusan
                ]);

                $stmtDel = $db->prepare("DELETE FROM member_pending WHERE id = :pid");
                $stmtDel->execute([':pid' => $pid]);

                $db->commit();
                $notif_html = '<div class="v-alert v-alert-success">Anggota <strong>' . htmlspecialchars($data['member_name'], ENT_QUOTES, 'UTF-8') . ' (' . htmlspecialchars($data['member_id'], ENT_QUOTES, 'UTF-8') . ')</strong> berhasil disetujui dan resmi masuk ke Daftar Anggota!</div>';
            } catch (Exception $e) {
                $db->rollBack();
                $notif_html = '<div class="v-alert v-alert-danger">Gagal menyetujui pendaftaran: ' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . '</div>';
            }
        } elseif ($aksi === 'reject') {
            if (!empty($data['member_image'])) {
                $file_path = IMGBS . 'persons/' . basename($data['member_image']);
                if (file_exists($file_path)) {
                    @unlink($file_path);
                }
            }

            $stmtDel = $db->prepare("DELETE FROM member_pending WHERE id = :pid");
            $stmtDel->execute([':pid' => $pid]);
            $notif_html = '<div class="v-alert v-alert-warning">Pendaftaran <strong>' . htmlspecialchars($data['member_name'], ENT_QUOTES, 'UTF-8') . '</strong> telah ditolak dan dihapus.</div>';
        }
    }
}

$pendingList = $db->query("
    SELECT p.*, t.member_type_name 
    FROM member_pending p 
    LEFT JOIN mst_member_type t ON p.member_type_id = t.member_type_id 
    ORDER BY p.input_date DESC
")->fetchAll(PDO::FETCH_ASSOC);

$totalPending = count($pendingList);
?>

<style>
    .verif-wrap {
        padding: 1.25rem 1.5rem 2.5rem;
        background: #f4f7fb;
        min-height: calc(100vh - 110px);
    }

    /* Header Banner */
    .verif-header-card {
        background: linear-gradient(135deg, #1e3a8a 0%, #2563eb 100%);
        color: #ffffff;
        border-radius: 14px;
        padding: 1.4rem 1.75rem;
        margin-bottom: 1.25rem;
        display: flex;
        flex-wrap: wrap;
        justify-content: space-between;
        align-items: center;
        gap: 1rem;
        box-shadow: 0 8px 24px rgba(30, 58, 138, 0.16);
    }
    .verif-header-title h2 {
        margin: 0 0 0.25rem;
        font-size: 1.35rem;
        font-weight: 700;
        color: #ffffff;
    }
    .verif-header-title p {
        margin: 0;
        font-size: 0.88rem;
        color: rgba(255, 255, 255, 0.86);
    }
    .verif-stat-pill {
        background: rgba(255, 255, 255, 0.16);
        border: 1px solid rgba(255, 255, 255, 0.28);
        backdrop-filter: blur(6px);
        padding: 0.55rem 1.1rem;
        border-radius: 999px;
        display: flex;
        align-items: center;
        gap: 0.6rem;
        font-size: 0.88rem;
        font-weight: 600;
    }
    .verif-stat-count {
        background: #ffffff;
        color: #1e3a8a;
        font-weight: 800;
        padding: 0.15rem 0.6rem;
        border-radius: 999px;
        font-size: 0.9rem;
    }

    /* Notifikasi Elegan */
    .v-alert {
        padding: 0.95rem 1.25rem;
        border-radius: 10px;
        margin-bottom: 1.25rem;
        font-size: 0.9rem;
        border-left: 4px solid;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.04);
    }
    .v-alert-success { background: #ecfdf5; color: #065f46; border-color: #10b981; }
    .v-alert-danger  { background: #fef2f2; color: #991b1b; border-color: #ef4444; }
    .v-alert-warning { background: #fffbeb; color: #92400e; border-color: #f59e0b; }
    .v-alert-info    { background: #eff6ff; color: #1e40af; border-color: #3b82f6; }

    /* Card & Toolbar Tabel */
    .verif-table-card {
        background: #ffffff;
        border-radius: 14px;
        box-shadow: 0 4px 20px rgba(15, 23, 42, 0.05);
        border: 1px solid #e2e8f0;
        overflow: hidden;
    }
    .verif-toolbar {
        padding: 1rem 1.5rem;
        border-bottom: 1px solid #eef2f6;
        display: flex;
        flex-wrap: wrap;
        justify-content: space-between;
        align-items: center;
        gap: 0.75rem;
        background: #ffffff;
    }
    .verif-search-box {
        position: relative;
        width: 100%;
        max-width: 340px;
    }
    .verif-search-input {
        width: 100%;
        padding: 0.55rem 0.95rem 0.55rem 2.3rem;
        border: 1.5px solid #cbd5e1;
        border-radius: 9px;
        font-size: 0.88rem;
        color: #1e293b;
        background: #f8fafc;
        transition: all 0.2s;
    }
    .verif-search-input:focus {
        background: #ffffff;
        border-color: #2563eb;
        outline: none;
        box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.12);
    }
    .verif-search-icon {
        position: absolute;
        left: 0.8rem;
        top: 50%;
        transform: translateY(-50%);
        color: #94a3b8;
        font-size: 0.9rem;
        pointer-events: none;
    }

    /* Tabel Modern */
    .verif-table {
        width: 100%;
        border-collapse: collapse;
        margin: 0;
    }
    .verif-table thead th {
        background: #f8fafc;
        color: #475569;
        font-size: 0.76rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        padding: 0.9rem 1.15rem;
        border-bottom: 1px solid #e2e8f0;
        white-space: nowrap;
    }
    .verif-table tbody tr {
        border-bottom: 1px solid #f1f5f9;
        transition: background 0.15s ease;
    }
    .verif-table tbody tr:last-child { border-bottom: none; }
    .verif-table tbody tr:hover { background: #f8fafc; }
    .verif-table td {
        padding: 1rem 1.15rem;
        vertical-align: middle;
        font-size: 0.88rem;
        color: #1e293b;
    }

    /* Avatar & Info Pemustaka */
    .v-member-cell {
        display: flex;
        align-items: center;
        gap: 0.85rem;
    }
    .v-avatar {
        width: 46px;
        height: 46px;
        border-radius: 50%;
        object-fit: cover;
        border: 2px solid #e2e8f0;
        flex-shrink: 0;
        cursor: pointer;
        transition: transform 0.2s, border-color 0.2s;
    }
    .v-avatar:hover {
        transform: scale(1.08);
        border-color: #2563eb;
    }
    .v-avatar-placeholder {
        width: 46px;
        height: 46px;
        border-radius: 50%;
        background: linear-gradient(135deg, #dbeafe 0%, #bfdbfe 100%);
        color: #1d4ed8;
        font-weight: 700;
        font-size: 1rem;
        display: flex;
        align-items: center;
        justify-content: center;
        flex-shrink: 0;
        border: 2px solid #eff6ff;
    }
    .v-member-name {
        font-weight: 700;
        color: #0f172a;
        font-size: 0.93rem;
        line-height: 1.3;
    }
    .v-id-badge {
        display: inline-block;
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-size: 0.78rem;
        font-weight: 600;
        color: #334155;
        background: #f1f5f9;
        padding: 0.12rem 0.5rem;
        border-radius: 5px;
        margin-top: 0.2rem;
    }
    .v-type-pill {
        display: inline-block;
        font-size: 0.74rem;
        font-weight: 600;
        color: #1d4ed8;
        background: #eff6ff;
        border: 1px solid #dbeafe;
        padding: 0.15rem 0.55rem;
        border-radius: 999px;
        margin-top: 0.25rem;
    }
    .v-subtext {
        display: block;
        color: #64748b;
        font-size: 0.8rem;
        margin-top: 0.15rem;
    }

    /* Tombol Aksi */
    .v-action-group {
        display: flex;
        align-items: center;
        gap: 0.4rem;
        flex-wrap: nowrap;
    }
    .v-btn {
        border: none;
        border-radius: 8px;
        padding: 0.42rem 0.75rem;
        font-size: 0.8rem;
        font-weight: 600;
        cursor: pointer;
        transition: all 0.18s ease;
        display: inline-flex;
        align-items: center;
        gap: 0.3rem;
        white-space: nowrap;
    }
    .v-btn-edit { background: #eff6ff; color: #1d4ed8; border: 1px solid #bfdbfe; }
    .v-btn-edit:hover { background: #2563eb; color: #ffffff; }
    .v-btn-approve { background: #10b981; color: #ffffff; box-shadow: 0 2px 6px rgba(16, 185, 129, 0.25); }
    .v-btn-approve:hover { background: #059669; }
    .v-btn-reject { background: #fef2f2; color: #dc2626; border: 1px solid #fecaca; }
    .v-btn-reject:hover { background: #dc2626; color: #ffffff; }

    /* Empty State */
    .v-empty-state {
        text-align: center;
        padding: 3.5rem 1.5rem;
        color: #64748b;
    }
    .v-empty-icon {
        width: 56px;
        height: 56px;
        border-radius: 50%;
        background: #eff6ff;
        color: #2563eb;
        font-size: 1.5rem;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        margin-bottom: 0.85rem;
    }

    /* Modal Edit & Pratinjau Foto */
    .verif-modal-backdrop {
        display: none;
        position: fixed;
        top: 0; left: 0; width: 100%; height: 100%;
        background: rgba(15, 23, 42, 0.65);
        backdrop-filter: blur(3px);
        z-index: 9999;
        align-items: center;
        justify-content: center;
        padding: 15px;
    }
    .verif-modal-box {
        background: #ffffff;
        border-radius: 14px;
        width: 100%;
        max-width: 660px;
        max-height: 90vh;
        overflow-y: auto;
        box-shadow: 0 20px 40px rgba(15, 23, 42, 0.25);
        animation: modalFadeIn 0.2s ease-out;
    }
    @keyframes modalFadeIn {
        from { opacity: 0; transform: translateY(-10px); }
        to { opacity: 1; transform: translateY(0); }
    }
    .verif-modal-header {
        padding: 1.1rem 1.5rem;
        background: linear-gradient(135deg, #1e3a8a 0%, #2563eb 100%);
        color: #ffffff;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    .verif-modal-body { padding: 1.5rem; }
    .verif-modal-body label {
        font-size: 0.82rem;
        color: #334155;
        margin-bottom: 0.3rem;
        display: block;
    }
    .verif-modal-body .form-control {
        border-radius: 8px;
        border: 1.5px solid #cbd5e1;
        font-size: 0.88rem;
    }
    .verif-modal-body .form-control:focus {
        border-color: #2563eb;
        box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.12);
    }
    .verif-modal-footer {
        padding: 1rem 1.5rem;
        background: #f8fafc;
        border-top: 1px solid #e2e8f0;
        display: flex;
        justify-content: flex-end;
        gap: 0.6rem;
    }
</style>

<div class="verif-wrap">
    <!-- Header Banner -->
    <div class="verif-header-card">
        <div class="verif-header-title">
            <h2>Verifikasi Pendaftaran Anggota Mandiri</h2>
            <p>Tinjau, perbarui data jika diperlukan, dan setujui permohonan keanggotaan baru</p>
        </div>
        <div class="verif-stat-pill">
            <span>Menunggu Verifikasi</span>
            <span class="verif-stat-count"><?= $totalPending ?></span>
        </div>
    </div>

    <?= $notif_html ?>

    <!-- Kontainer Tabel -->
    <div class="verif-table-card">
        <div class="verif-toolbar">
            <div class="verif-search-box">
                <span class="verif-search-icon">&#128269;</span>
                <input type="text" id="verifSearchInput" class="verif-search-input" placeholder="Cari NIM, nama, fakultas, atau email...">
            </div>
            <div style="font-size: 0.82rem; color: #64748b;">
                Klik foto untuk memperbesar pratinjau
            </div>
        </div>

        <div class="table-responsive">
            <table class="verif-table" id="verifTable">
                <thead>
                    <tr>
                        <th>Pemustaka</th>
                        <th>Tgl Lahir</th>
                        <th>Akademik</th>
                        <th>Kontak</th>
                        <th>Waktu Daftar</th>
                        <th style="width: 215px;">Aksi</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if ($totalPending === 0): ?>
                        <tr>
                            <td colspan="6">
                                <div class="v-empty-state">
                                    <div class="v-empty-icon">&#10003;</div>
                                    <h5 style="color: #1e293b; font-weight: 700; margin-bottom: 0.3rem;">Semua Pendaftaran Sudah Diverifikasi</h5>
                                    <p style="margin: 0; font-size: 0.88rem;">Belum ada antrean pendaftaran anggota mandiri yang baru masuk.</p>
                                </div>
                            </td>
                        </tr>
                    <?php else: ?>
                        <?php foreach ($pendingList as $row): 
                            $inisial = strtoupper(mb_substr(trim($row['member_name'] ?? 'A'), 0, 1));
                            $fotoUrl = !empty($row['member_image']) ? SWB . 'images/persons/' . htmlspecialchars(basename($row['member_image']), ENT_QUOTES, 'UTF-8') : '';
                        ?>
                            <tr class="verif-row">
                                <td>
                                    <div class="v-member-cell">
                                        <?php if ($fotoUrl): ?>
                                            <img src="<?= $fotoUrl ?>" alt="Foto" class="v-avatar" onclick="lihatFotoBesar('<?= $fotoUrl ?>', '<?= htmlspecialchars($row['member_name'], ENT_QUOTES, 'UTF-8') ?>')">
                                        <?php else: ?>
                                            <div class="v-avatar-placeholder"><?= htmlspecialchars($inisial, ENT_QUOTES, 'UTF-8') ?></div>
                                        <?php endif; ?>
                                        <div>
                                            <div class="v-member-name"><?= htmlspecialchars($row['member_name'], ENT_QUOTES, 'UTF-8') ?></div>
                                            <span class="v-id-badge"><?= htmlspecialchars($row['member_id'], ENT_QUOTES, 'UTF-8') ?></span>
                                            <span class="v-type-pill"><?= htmlspecialchars($row['member_type_name'] ?? 'Anggota', ENT_QUOTES, 'UTF-8') ?></span>
                                        </div>
                                    </div>
                                </td>
                                <td>
                                    <span style="font-weight: 500;"><?= htmlspecialchars(date('d M Y', strtotime($row['birth_date'])), ENT_QUOTES, 'UTF-8') ?></span>
                                    <span class="v-subtext"><?= ((int)$row['gender'] === 1) ? 'Laki-laki' : 'Perempuan' ?></span>
                                </td>
                                <td>
                                    <strong style="color: #1e293b; font-size: 0.85rem;"><?= htmlspecialchars($row['fakultas'] ?? '-', ENT_QUOTES, 'UTF-8') ?></strong>
                                    <span class="v-subtext"><?= htmlspecialchars($row['jurusan'] ?? '-', ENT_QUOTES, 'UTF-8') ?></span>
                                </td>
                                <td>
                                    <span style="font-weight: 500;"><?= htmlspecialchars($row['member_email'], ENT_QUOTES, 'UTF-8') ?></span>
                                    <span class="v-subtext"><?= htmlspecialchars($row['member_phone'] ?? '-', ENT_QUOTES, 'UTF-8') ?></span>
                                </td>
                                <td>
                                    <span style="font-weight: 500;"><?= htmlspecialchars(date('d M Y', strtotime($row['input_date'])), ENT_QUOTES, 'UTF-8') ?></span>
                                    <span class="v-subtext">Pukul <?= htmlspecialchars(date('H:i', strtotime($row['input_date'])), ENT_QUOTES, 'UTF-8') ?></span>
                                </td>
                                <td>
                                    <?php if ($can_write): ?>
                                        <div class="v-action-group">
                                            <button type="button" class="v-btn v-btn-edit" 
                                                    onclick='bukaModalEdit(<?= json_encode($row, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP) ?>)'>
                                                Edit
                                            </button>

                                            <form method="POST" action="<?= htmlspecialchars($plugin_url, ENT_QUOTES, 'UTF-8') ?>" class="ajax-verif-form" style="margin:0;" data-confirm="Setujui dan masukkan ke Daftar Anggota aktif?">
                                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_admin_verif'], ENT_QUOTES, 'UTF-8') ?>">
                                                <input type="hidden" name="pending_id" value="<?= (int)$row['id'] ?>">
                                                <input type="hidden" name="aksi_verif" value="approve">
                                                <button type="submit" class="v-btn v-btn-approve">Setujui</button>
                                            </form>

                                            <form method="POST" action="<?= htmlspecialchars($plugin_url, ENT_QUOTES, 'UTF-8') ?>" class="ajax-verif-form" style="margin:0;" data-confirm="Tolak dan hapus permanen pendaftaran ini?">
                                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_admin_verif'], ENT_QUOTES, 'UTF-8') ?>">
                                                <input type="hidden" name="pending_id" value="<?= (int)$row['id'] ?>">
                                                <input type="hidden" name="aksi_verif" value="reject">
                                                <button type="submit" class="v-btn v-btn-reject">Tolak</button>
                                            </form>
                                        </div>
                                    <?php else: ?>
                                        <span class="badge badge-secondary">Hanya Lihat</span>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>

<!-- Modal Pratinjau Foto Besar -->
<div id="modalPreviewFoto" class="verif-modal-backdrop" onclick="this.style.display='none'">
    <div style="background:#fff; padding:1rem; border-radius:14px; max-width:380px; text-align:center; box-shadow:0 20px 40px rgba(0,0,0,0.3);" onclick="event.stopPropagation()">
        <img id="imgPreviewBesar" src="" alt="Pas Foto" style="width:100%; max-height:380px; object-fit:cover; border-radius:10px; margin-bottom:0.75rem;">
        <div id="namaPreviewBesar" style="font-weight:700; color:#0f172a; margin-bottom:0.75rem;"></div>
        <button type="button" class="btn btn-sm btn-secondary" onclick="document.getElementById('modalPreviewFoto').style.display='none'">Tutup Pratinjau</button>
    </div>
</div>

<!-- Modal Form Edit Data Pendaftar -->
<div id="modalEditPendaftar" class="verif-modal-backdrop">
    <div class="verif-modal-box">
        <div class="verif-modal-header">
            <h5 class="mb-0" style="font-size: 1.05rem; font-weight: 700;">Edit Data Pendaftar Sebelum Disetujui</h5>
            <button type="button" onclick="tutupModalEdit()" style="background:none; border:none; color:#fff; font-size:1.4rem; line-height:1; cursor:pointer;">&times;</button>
        </div>
        <form method="POST" action="<?= htmlspecialchars($plugin_url, ENT_QUOTES, 'UTF-8') ?>" class="ajax-verif-form">
            <div class="verif-modal-body">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_admin_verif'], ENT_QUOTES, 'UTF-8') ?>">
                <input type="hidden" name="pending_id" id="edit_pending_id">
                <input type="hidden" name="aksi_verif" value="edit_save">

                <div class="row">
                    <div class="col-md-6 mb-3">
                        <label class="font-weight-bold">ID / NIM</label>
                        <input type="text" name="member_id" id="edit_member_id" class="form-control" required>
                    </div>
                    <div class="col-md-6 mb-3">
                        <label class="font-weight-bold">Nama Lengkap</label>
                        <input type="text" name="member_name" id="edit_member_name" class="form-control" required>
                    </div>
                </div>

                <div class="row">
                    <div class="col-md-4 mb-3">
                        <label class="font-weight-bold">Tanggal Lahir</label>
                        <input type="date" name="birth_date" id="edit_birth_date" class="form-control" required>
                    </div>
                    <div class="col-md-4 mb-3">
                        <label class="font-weight-bold">Jenis Kelamin</label>
                        <select name="gender" id="edit_gender" class="form-control">
                            <option value="1">Laki-laki</option>
                            <option value="0">Perempuan</option>
                        </select>
                    </div>
                    <div class="col-md-4 mb-3">
                        <label class="font-weight-bold">Tipe Anggota</label>
                        <select name="member_type_id" id="edit_member_type_id" class="form-control">
                            <?php foreach ($memberTypes as $mt): ?>
                                <option value="<?= (int)$mt['member_type_id'] ?>">
                                    <?= htmlspecialchars($mt['member_type_name'], ENT_QUOTES, 'UTF-8') ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                </div>

                <div class="row">
                    <div class="col-md-6 mb-3">
                        <label class="font-weight-bold">Fakultas</label>
                        <select name="fakultas" id="edit_fakultas" class="form-control">
                            <option value="">-- Pilih Fakultas --</option>
                            <?php foreach ($opsiFakultas as $fak): ?>
                                <option value="<?= htmlspecialchars($fak, ENT_QUOTES, 'UTF-8') ?>"><?= htmlspecialchars($fak, ENT_QUOTES, 'UTF-8') ?></option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div class="col-md-6 mb-3">
                        <label class="font-weight-bold">Jurusan / Prodi</label>
                        <select name="jurusan" id="edit_jurusan" class="form-control">
                            <option value="">-- Pilih Jurusan --</option>
                            <?php foreach ($opsiJurusan as $jur): ?>
                                <option value="<?= htmlspecialchars($jur, ENT_QUOTES, 'UTF-8') ?>"><?= htmlspecialchars($jur, ENT_QUOTES, 'UTF-8') ?></option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                </div>

                <div class="row">
                    <div class="col-md-6 mb-3">
                        <label class="font-weight-bold">Email</label>
                        <input type="email" name="member_email" id="edit_member_email" class="form-control" required>
                    </div>
                    <div class="col-md-6 mb-3">
                        <label class="font-weight-bold">No. HP / WhatsApp</label>
                        <input type="text" name="member_phone" id="edit_member_phone" class="form-control">
                    </div>
                </div>

                <div class="mb-3">
                    <label class="font-weight-bold">Instansi / Unit Kerja (Opsional)</label>
                    <input type="text" name="inst_name" id="edit_inst_name" class="form-control">
                </div>

                <div class="mb-1">
                    <label class="font-weight-bold">Alamat</label>
                    <textarea name="member_address" id="edit_member_address" class="form-control" rows="2"></textarea>
                </div>
            </div>
            <div class="verif-modal-footer">
                <button type="button" class="btn btn-light border" onclick="tutupModalEdit()">Batal</button>
                <button type="submit" class="btn btn-primary" style="background:#2563eb; border-color:#2563eb; font-weight:600;">Simpan Perubahan</button>
            </div>
        </form>
    </div>
</div>

<script>
function lihatFotoBesar(url, nama) {
    document.getElementById('imgPreviewBesar').src = url;
    document.getElementById('namaPreviewBesar').textContent = nama;
    document.getElementById('modalPreviewFoto').style.display = 'flex';
}

function bukaModalEdit(data) {
    document.getElementById('edit_pending_id').value     = data.id || '';
    document.getElementById('edit_member_id').value      = data.member_id || '';
    document.getElementById('edit_member_name').value    = data.member_name || '';
    document.getElementById('edit_birth_date').value     = data.birth_date || '';
    document.getElementById('edit_gender').value         = data.gender !== undefined ? data.gender : '1';
    document.getElementById('edit_member_type_id').value = data.member_type_id || '1';
    document.getElementById('edit_fakultas').value       = data.fakultas || '';
    document.getElementById('edit_jurusan').value        = data.jurusan || '';
    document.getElementById('edit_member_email').value   = data.member_email || '';
    document.getElementById('edit_member_phone').value   = data.member_phone || '';
    document.getElementById('edit_inst_name').value      = data.inst_name || '';
    document.getElementById('edit_member_address').value = data.member_address || '';

    document.getElementById('modalEditPendaftar').style.display = 'flex';
}

function tutupModalEdit() {
    document.getElementById('modalEditPendaftar').style.display = 'none';
}

// Pencarian Instan pada Tabel Antrean
const searchInput = document.getElementById('verifSearchInput');
if (searchInput) {
    searchInput.addEventListener('input', function() {
        const keyword = this.value.toLowerCase().trim();
        document.querySelectorAll('#verifTable tbody .verif-row').forEach(function(row) {
            const text = row.textContent.toLowerCase();
            row.style.display = text.includes(keyword) ? '' : 'none';
        });
    });
}

// Tangani submit form secara AJAX ke endpoint plugin SLiMS dan muat ulang kontainer utama
document.querySelectorAll('.ajax-verif-form').forEach(function(form) {
    form.addEventListener('submit', function(e) {
        e.preventDefault();
        const confirmMsg = form.getAttribute('data-confirm');
        if (confirmMsg && !confirm(confirmMsg)) {
            return;
        }

        const formData = new FormData(form);
        fetch(form.getAttribute('action'), {
            method: 'POST',
            body: formData,
            credentials: 'same-origin'
        })
        .then(response => response.text())
        .then(html => {
            tutupModalEdit();
            const mainContent = document.getElementById('mainContent');
            if (mainContent) {
                mainContent.innerHTML = html;
                mainContent.querySelectorAll('script').forEach(oldScript => {
                    const newScript = document.createElement('script');
                    newScript.textContent = oldScript.textContent;
                    document.body.appendChild(newScript);
                    newScript.remove();
                });
            } else {
                location.reload();
            }
        })
        .catch(err => {
            alert('Terjadi kesalahan koneksi saat memproses verifikasi: ' + err);
        });
    });
});
</script>