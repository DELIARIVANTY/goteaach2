$(document).ready(function () {
    // Fungsi untuk memberikan pesan saat tautan di klik
    function handleLinkClick(event) {
        event.preventDefault();
        const linkText = $(this).text();
        alert(`${linkText} feature is not yet implemented!`);
    }

    // Memilih semua elemen tautan dalam dashboard-item dan menambahkan event listener
    $('.dashboard-item a').on('click', handleLinkClick);

    // Fungsi untuk animasi masuk (fade-in) ketika halaman dimuat
    $('.dashboard-item').each(function (index) {
        $(this).delay(index * 200).animate({
            opacity: 1,
            // jQuery animate tidak mendukung properti 'transform' secara langsung.
            // Jadi, kita gunakan CSS class untuk transformasi.
        }, 500);
    });

    // Menambahkan class untuk mengatur transformasi setelah animasi fade-in
    $('.dashboard-item').each(function () {
        $(this).css('transform', 'translateY(0)');
    });

    // Animasi hover pada setiap dashboard-item
    $('.dashboard-item').hover(
        function () {
            $(this).css({
                transform: 'scale(1.05)',
                boxShadow: '0px 4px 15px rgba(0, 0, 0, 0.2)'
            });
        },
        function () {
            $(this).css({
                transform: 'scale(1)',
                boxShadow: 'none'
            });
        }
    );

    // Pesan selamat datang dinamis berdasarkan waktu
    const currentHour = new Date().getHours();
    let greeting;

    if (currentHour < 12) {
        greeting = "Good Morning";
    } else if (currentHour < 18) {
        greeting = "Good Afternoon";
    } else {
        greeting = "Good Evening";
    }

    $('.jumbotron h1').text(greeting);

    // Fungsi untuk menampilkan waktu dan tanggal saat ini di footer
    function updateTime() {
        const currentTime = new Date();
        const formattedTime = currentTime.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        const formattedDate = currentTime.toLocaleDateString();
        $('footer p').html(`&copy; 2024 Go-Teach Apps. All Rights Reserved.<br> Current time: ${formattedDate}, ${formattedTime}`);
    }

    // Perbarui waktu setiap 1 menit
    setInterval(updateTime, 60000);
    updateTime(); // Memanggil fungsi saat halaman dimuat

    // === Tambahan Fitur ===

    // 1. Smooth Scroll untuk Tautan dengan Hash (#)
    $('a[href*="#"]').on('click', function (event) {
        // Pastikan hash memiliki nilai sebelum menggulir
        if (this.hash !== "") {
            event.preventDefault();
            const hash = this.hash;

            $('html, body').animate({
                scrollTop: $(hash).offset().top
            }, 800, function () {
                window.location.hash = hash;
            });
        }
    });

    // 2. Menambahkan Tooltips pada Tautan
    // Inisialisasi tooltips Bootstrap 5
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Menambahkan atribut tooltip pada semua tautan di dashboard-item
    $('.dashboard-item a').attr('data-bs-toggle', 'tooltip').attr('title', 'Click to explore this feature!');

    // 3. Konfirmasi Sebelum Logout
    $('a[href="signin.html"]').on('click', function (event) {
        const confirmLogout = confirm("Are you sure you want to logout?");
        if (!confirmLogout) {
            event.preventDefault();
        }
    });

    
    // 5. Menambahkan Efek Accordion pada Seksi Informasi
    $('.dashboard-item h3').on('click', function () {
        $(this).next('p').slideToggle(); // Menampilkan/menyembunyikan deskripsi di bawah judul saat diklik
    });

    // Sembunyikan deskripsi saat halaman dimuat
    $('.dashboard-item p').hide();

    // 6. Filter Dashboard Items
    $('#search').on('keyup', function () {
        const searchTerm = $(this).val().toLowerCase();
        $('.dashboard-item').filter(function () {
            $(this).toggle($(this).text().toLowerCase().indexOf(searchTerm) > -1);
        });
    });

    // === Penambahan CSS untuk Animasi Transformasi ===
    // Menambahkan CSS melalui jQuery
    $('head').append(`
    <style>
        .dashboard-item {
            opacity: 0;
            transform: translateY(20px);
            transition: opacity 0.5s ease, transform 0.5s ease;
        }

        .dashboard-item.show {
            opacity: 1;
            transform: translateY(0);
        }

        .dashboard-item:hover {
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }

        .btn-primary:hover {
            background-color: #0056b3;
            transition: background-color 0.3s ease;
        }
    </style>
    `);
});

// Mengubah semua ukuran font-size
$('document').ready(function() {
    $("#one").click(function() {
        $("html").css("font-size", "12px");
    })
    $("#two").click(function() {
        $("html").css("font-size", "16px");
    })
    $("#three").click(function() {
        $("html").css("font-size", "20px");
    })
    })
