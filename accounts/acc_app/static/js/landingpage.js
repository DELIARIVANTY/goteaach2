document.addEventListener('DOMContentLoaded', function() {
    // Ambil semua tombol dengan class 'choose-plan'
    const choosePlanButtons = document.querySelectorAll('.choose-plan');
    
    // Loop melalui semua tombol dan tambahkan event listener
    choosePlanButtons.forEach(function(button) {
        button.addEventListener('click', function(event) {
            event.preventDefault(); // Mencegah link untuk melakukan navigasi
            alert("You have selected the Subscription!");
        });
    });
});

// Teks testimonial yang ingin ditampilkan dengan efek pengetikan
const testimonialText = "";
const typingSpeed = 50; // Kecepatan pengetikan dalam milidetik
const testimonialElement = document.getElementById('testimonial');
let index = 0; // Index untuk melacak karakter yang sedang ditampilkan

// Fungsi untuk menampilkan teks dengan efek pengetikan
function type() {
    if (index < testimonialText.length) {
        testimonialElement.innerHTML += testimonialText.charAt(index); // Tambahkan karakter ke elemen
        index++;
        setTimeout(type, typingSpeed); // Panggil fungsi ini lagi setelah jeda
    }
}

// Mulai efek pengetikan
type();

$(document).ready(function() {
    // Typewriter effect for testimonials
    let testimonialText1 = "Go Teach telah membantu saya meningkatkan kemampuan belajar online dengan cepat dan mudah!";
    let testimonialText2 = "Go Teach menyediakan berbagai pilihan mata pelajaran yang luas. Saya berhasil menemukan instruktur bahasa asing yang membantu saya belajar dengan cepat dan efektif. Sangat saya rekomendasikan!";
    let index1 = 0, index2 = 0;

    function typeWriter1() {
        if (index1 < testimonialText1.length) {
            $('#testimonial').append(testimonialText1.charAt(index1));
            index1++;
            setTimeout(typeWriter1, 50);
        }
    }

    function typeWriter2() {
        if (index2 < testimonialText2.length) {
            $('#testimonial2').append(testimonialText2.charAt(index2));
            index2++;
            setTimeout(typeWriter2, 50);
        }
    }

    // Start the typewriter effect for both testimonials
    typeWriter1();
    setTimeout(typeWriter2, 3000); // Delay for the second testimonial to start after the first

    // Back to Top functionality
    $(window).scroll(function() {
        if ($(this).scrollTop() > 300) {
            $('.back-to-top').fadeIn();
        } else {
            $('.back-to-top').fadeOut();
        }
    });

    // Smooth scroll to the top when the "Back to Top" button is clicked
    $('.back-to-top').click(function(e) {
        e.preventDefault();
        $('html, body').animate({scrollTop: 0}, '300');
    });
});
