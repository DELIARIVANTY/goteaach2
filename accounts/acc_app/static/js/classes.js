// Memastikan DOM siap sebelum menjalankan JavaScript
document.addEventListener("DOMContentLoaded", function () {
  // Fungsi untuk memberikan pesan saat tautan kelas diklik
  function handleClassLinkClick(event) {
    event.preventDefault();
    const classTitle = event.target
      .closest(".card-body")
      .querySelector(".card-title").innerText;
    alert(`${classTitle} saat ini tidak tersedia. Silakan coba lagi nanti.`);
  }

  // Memilih semua tautan "Masuk Kelas"
  const classLinks = document.querySelectorAll(".card .btn-primary");

  // Menambahkan event listener ke setiap tautan "Masuk Kelas"
  classLinks.forEach((link) => {
    link.addEventListener("click", handleClassLinkClick);
  });

  // Animasi fade-in untuk kartu kelas saat halaman dimuat
  const classCards = document.querySelectorAll(".card");
  classCards.forEach((card, index) => {
    setTimeout(() => {
      card.style.opacity = "1";
      card.style.transform = "translateY(0)";
    }, index * 200); // Animasi berurutan setiap 200ms
  });

  // Animasi hover pada setiap kartu
  classCards.forEach((card) => {
    card.addEventListener("mouseover", function () {
      card.style.transform = "scale(1.05)"; // Menambahkan efek zoom saat hover
      card.style.boxShadow = "0px 4px 15px rgba(0, 0, 0, 0.2)"; // Menambahkan shadow
    });
    card.addEventListener("mouseout", function () {
      card.style.transform = "scale(1)"; // Mengembalikan ukuran normal
      card.style.boxShadow = "none"; // Menghilangkan shadow
    });
  });

  // Fungsi untuk menampilkan waktu dan tanggal saat ini di footer
  function updateTime() {
    const footer = document.querySelector("footer p");
    const currentTime = new Date();
    const formattedTime = currentTime.toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
    });
    const formattedDate = currentTime.toLocaleDateString();
    footer.innerHTML = `&copy; 2024 Go-Teach Apps. Hak Cipta Dilindungi. <br> Waktu saat ini: ${formattedDate}, ${formattedTime}`;
  }

  // Perbarui waktu setiap 1 menit
  setInterval(updateTime, 60000);
  updateTime(); // Memanggil fungsi saat halaman dimuat

  // Search jobs by title
  $("#jobSearch").on("keyup", function () {
    var searchText = $(this).val().toLowerCase();

    $(".job-card").each(function () {
      var jobTitle = $(this).find(".card-title").text().toLowerCase();
      if (jobTitle.includes(searchText)) {
        $(this).show();
      } else {
        $(this).hide();
      }
    });
  });
});

// CSS tambahan untuk efek animasi dan hover
document.write(`
<style>
    .card {
        opacity: 0;
        transform: translateY(20px);
        transition: opacity 0.5s ease, transform 0.5s ease;
    }

    .card:hover {
        transition: transform 0.3s ease, box-shadow 0.3s ease;
    }

    .btn-primary:hover {
        background-color: #0056b3;
        transition: background-color 0.3s ease;
    }
</style>
`); 