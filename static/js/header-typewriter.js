document.addEventListener('DOMContentLoaded', () => {
    const sentences = [
        "Hello friend.",
        "Hello friend? That's lame..",
    ];
    const element = document.getElementById('typewriter-text');
    let sentenceIndex = 0;
    let charIndex = 0;
    let isDeleting = false;
    let typeSpeed = 100;

    function typeWriter() {
        const currentSentence = sentences[sentenceIndex];

        if (isDeleting) {
            element.textContent = currentSentence.substring(0, charIndex - 1);
            charIndex--;
            typeSpeed = 30; // Faster deleting
        } else {
            element.textContent = currentSentence.substring(0, charIndex + 1);
            charIndex++;
            typeSpeed = 80 - Math.random() * 50; // Faster random typing speed

            // Specific pause for "Hello friend? That's lame..."
            if (currentSentence.includes("That's lame") && currentSentence[charIndex - 1] === '?') {
                typeSpeed = 1000; // 1 second pause
            }
        }

        if (!isDeleting && charIndex === currentSentence.length) {
            // Finished typing sentence
            // Wait before deleting
            typeSpeed = 2000;
            isDeleting = true;
        } else if (isDeleting && charIndex === 0) {
            // Finished deleting sentence
            isDeleting = false;
            sentenceIndex++;
            if (sentenceIndex >= sentences.length) {
                sentenceIndex = 0;
            }
            typeSpeed = 500; // Normal pause before next sentence
        }

        setTimeout(typeWriter, typeSpeed);
    }

    // Start typing after a short delay
    setTimeout(typeWriter, 1000);
});
