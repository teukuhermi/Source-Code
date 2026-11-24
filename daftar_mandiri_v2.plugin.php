<?php
/**
 * Plugin Name: Pendaftaran Anggota Mandiri (v9.7.2 Ready)
 * Plugin URI: https://library.utu.ac.id
 * Description: Form registrasi anggota mandiri di OPAC & Library dengan antrean verifikasi pustakawan.
 * Version: 2.0.0
 * Author: Tim IT Perpustakaan UTU
 */

use SLiMS\Plugins;

$plugin = Plugins::getInstance();

// Daftarkan rute halaman OPAC (tanda hubung & garis bawah agar keduanya aman)
$plugin->registerMenu('opac', 'daftar-mandiri', __DIR__ . '/opac_daftar.php');
$plugin->registerMenu('opac', 'daftar_mandiri', __DIR__ . '/opac_daftar.php');

// Daftarkan rute API penerima data dari server library.utu.ac.id
$plugin->registerMenu('opac', 'api-daftar', __DIR__ . '/api_daftar.php');

// Daftarkan submenu di modul Membership Admin
$plugin->registerMenu('membership', 'Verifikasi Pendaftaran', __DIR__ . '/admin_verifikasi.php');