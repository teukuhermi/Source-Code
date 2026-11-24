<?php
// Endpoint API Penerima Pendaftaran dari Server Library
if (!defined('INDEX_AUTH')) {
    die('can not access this file directly');
}

use SLiMS\DB;

header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, X-API-KEY, Authorization');
header('Content-Type: application/json; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

$SECRET_API_KEY = 'UTU_PERPUS_API_KEY_2026_RAHASIA_987654';

// Ambil API Key dari berbagai kemungkinan header server (Apache/Nginx/CGI)
$client_key = $_SERVER['HTTP_X_API_KEY']
    ?? ($_SERVER['REDIRECT_HTTP_X_API_KEY'] ?? '');

if (!hash_equals($SECRET_API_KEY, $client_key)) {
    http_response_code(401);
    echo json_encode(['status' => 'error', 'message' => 'Akses ditolak: API Key tidak valid.']);
    exit;
}

$db = DB::getInstance();

// Mode GET: Ambil daftar Tipe Anggota, Fakultas, & Jurusan
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $types = $db->query("SELECT member_type_id, member_type_name FROM mst_member_type")->fetchAll(PDO::FETCH_ASSOC);

    $getCustom = function ($label) use ($db) {
        $stmt = $db->prepare("SELECT data FROM mst_custom_field WHERE primary_table = 'member' AND LOWER(label) = LOWER(:lbl) LIMIT 1");
        $stmt->execute([':lbl' => $label]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$row || empty($row['data'])) return [];

        $raw = json_decode($row['data'], true);
        if (!is_array($raw)) $raw = @unserialize($row['data']);
        if (!is_array($raw)) return [];

        $list = [];
        foreach ($raw as $item) {
            $teks = is_array($item) ? ($item[1] ?? ($item[0] ?? '')) : $item;
            if ($teks !== '') $list[] = (string)$teks;
        }
        return $list;
    };

    echo json_encode([
        'status'       => 'ok',
        'member_types' => $types,
        'fakultas'     => $getCustom('Fakultas'),
        'jurusan'      => $getCustom('Jurusan')
    ]);
    exit;
}

// Mode POST: Terima data pendaftaran
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        $member_id      = preg_replace('/[^a-zA-Z0-9\-]/', '', trim($_POST['member_id'] ?? ''));
        $member_name    = trim(strip_tags($_POST['member_name'] ?? ''));
        $birth_date     = trim($_POST['birth_date'] ?? '');
        $gender         = in_array((int)($_POST['gender'] ?? 1), [0, 1], true) ? (int)$_POST['gender'] : 1;
        $member_type_id = (int)($_POST['member_type_id'] ?? 1);
        $fakultas       = trim(strip_tags($_POST['fakultas'] ?? ''));
        $jurusan        = trim(strip_tags($_POST['jurusan'] ?? ''));
        $member_email   = filter_var(trim($_POST['member_email'] ?? ''), FILTER_VALIDATE_EMAIL);
        $member_phone   = preg_replace('/[^0-9\+]/', '', trim($_POST['member_phone'] ?? ''));
        $member_address = trim(strip_tags($_POST['member_address'] ?? ''));
        $inst_name      = trim(strip_tags($_POST['inst_name'] ?? ''));
        $password       = $_POST['mpasswd'] ?? '';

        if (empty($member_id) || empty($member_name) || empty($birth_date) || !$member_email || strlen($password) < 8) {
            echo json_encode(['status' => 'danger', 'message' => 'Data wajib tidak lengkap atau format email/password tidak valid.']);
            exit;
        }

        // Cek duplikasi di member & member_pending
        $cek1 = $db->prepare("SELECT member_id FROM member WHERE member_id = :mid LIMIT 1");
        $cek1->execute([':mid' => $member_id]);
        if ($cek1->rowCount() > 0) {
            echo json_encode(['status' => 'warning', 'message' => 'NIM / ID Anggota sudah terdaftar aktif di sistem perpustakaan.']);
            exit;
        }

        $cek2 = $db->prepare("SELECT member_id FROM member_pending WHERE member_id = :mid LIMIT 1");
        $cek2->execute([':mid' => $member_id]);
        if ($cek2->rowCount() > 0) {
            echo json_encode(['status' => 'warning', 'message' => 'Pendaftaran dengan NIM / ID tersebut sudah masuk dan sedang menunggu verifikasi pustakawan.']);
            exit;
        }

        // Proses Foto (Opsional)
        $nama_file_foto = '';
        if (isset($_FILES['member_image']) && $_FILES['member_image']['error'] === UPLOAD_ERR_OK) {
            $file = $_FILES['member_image'];
            $img_info = @getimagesize($file['tmp_name']);
            $finfo    = new finfo(FILEINFO_MIME_TYPE);
            $mime     = $finfo->file($file['tmp_name']);

            if ($img_info === false || !in_array($mime, ['image/jpeg', 'image/png'], true)) {
                echo json_encode(['status' => 'danger', 'message' => 'Format foto harus JPG atau PNG asli.']);
                exit;
            }

            $random_name = 'mbr_' . bin2hex(random_bytes(16));
            if ($mime === 'image/jpeg') {
                $src = @imagecreatefromjpeg($file['tmp_name']);
                if ($src) {
                    $nama_file_foto = $random_name . '.jpg';
                    $tujuan = IMGBS . 'persons/' . $nama_file_foto;
                    imagejpeg($src, $tujuan, 85);
                    imagedestroy($src);
                }
            } elseif ($mime === 'image/png') {
                $src = @imagecreatefrompng($file['tmp_name']);
                if ($src) {
                    $nama_file_foto = $random_name . '.png';
                    $tujuan = IMGBS . 'persons/' . $nama_file_foto;
                    imagepng($src, $tujuan, 6);
                    imagedestroy($src);
                }
            }
            if ($nama_file_foto !== '' && file_exists($tujuan)) {
                @chmod($tujuan, 0644);
            }
        }

        // Simpan ke tabel antrean `member_pending`
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

        $stmt = $db->prepare($sql);
        $ok = $stmt->execute([
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

        if ($ok) {
            echo json_encode(['status' => 'success', 'message' => 'Pendaftaran berhasil dikirim! Data Anda sedang menunggu persetujuan pustakawan.']);
        } else {
            echo json_encode(['status' => 'danger', 'message' => 'Gagal menyimpan data ke database SLiMS.']);
        }
    } catch (Throwable $e) {
        echo json_encode(['status' => 'danger', 'message' => 'Error Database/Server: ' . $e->getMessage()]);
    }
    exit;
}