function attack(move) {
    const charizardHpElem = document.getElementById('charizard-hp');
    const pikachuHpElem = document.getElementById('pikachu-hp');
    const messageElem = document.getElementById('message');

    let charizardHp = parseInt(charizardHpElem.textContent, 10);
    let pikachuHp = parseInt(pikachuHpElem.textContent, 10);

    // Attack damage based on move
    let attackDamage = 0;
    switch (move) {
        case 'flamethrower':
            attackDamage = Math.floor(Math.random() * 30) + 10; // Random damage between 10 and 40
            break;
        case 'scratch':
            attackDamage = Math.floor(Math.random() * 10) + 5;  // Random damage between 5 and 15
            break;
        case 'ember':
            attackDamage = Math.floor(Math.random() * 20) + 5;  // Random damage between 5 and 25
            break;
        default:
            attackDamage = 0;
    }

    // Charizard attacks Pikachu
    pikachuHp -= attackDamage;
    if (pikachuHp < 0) pikachuHp = 0;
    pikachuHpElem.textContent = pikachuHp;
    messageElem.textContent = `Charizard uses ${move} and deals ${attackDamage} damage!`;

    if (pikachuHp === 0) {
        messageElem.textContent = 'Pikachu fainted! You win!';
        showWinSequence();
        return;
    }

    setTimeout(() => {
        // Pikachu attacks Charizard
        const pikachuAttackDamage = Math.floor(Math.random() * 20) + 1; // Random damage between 1 and 20
        charizardHp -= pikachuAttackDamage;
        if (charizardHp < 0) charizardHp = 0;
        charizardHpElem.textContent = charizardHp;
        messageElem.textContent = ` Pikachu retaliates for ${pikachuAttackDamage} damage!`;

        if (charizardHp === 0) {
            messageElem.textContent = ' Charizard fainted! You lost :( ';
        }
    }, 500); // 1000 milliseconds = 1 second
}
function showWinSequence() {
    const winSequenceElem = document.getElementById('win-sequence');
    const images = winSequenceElem.getElementsByClassName('win-image');
    let index = 0;

    winSequenceElem.style.display = 'block'; // Show win sequence

    function displayNextImage() {
        if (index < images.length) {
            images[index].style.opacity = 1; // Show current image
            setTimeout(() => {
                images[index].style.opacity = 0; // Hide current image
                index++;
                displayNextImage();
            }, 750); // Show each image for 500 milliseconds
        } else {
            setTimeout(() => {
                winSequenceElem.style.display = 'none'; // Hide win sequence after showing all images
            }, 750); // Wait until the last image is hidden
        }
    }

    displayNextImage();
}


function resetGame() {
    document.getElementById('charizard-hp').textContent = '100';
    document.getElementById('pikachu-hp').textContent = '100';
    document.getElementById('message').textContent = 'Choose your attack!';
    document.getElementById('win-sequence').style.display = 'none'; // Hide win sequence on reset
}