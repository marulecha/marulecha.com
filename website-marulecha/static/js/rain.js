// Agisilaos Maroulis 
// https://github.com/marulecha
// 27-01-2023

const c = document.getElementById("matrix");
const ctx = c.getContext("2d");

c.width = window.innerWidth;
c.height = window.innerHeight;

const chars = " 010101 ニンジャ レタス ハッキング 1337 ";

//Font Init & How many characters fit in screen.
const fontSize = 16;
const columns = c.width/fontSize;
const matrixArray = [];

//Positioning Init.
for (let x = 0; x < columns; x++){
    matrixArray[x] = 1;
}

function rain(){     
    ctx.fillStyle = "rgba(0,0,0, 0.05)";
    ctx.fillRect(0, 0, c.width, c.height);

    // ctx.fillStyle = "#0093AF";
    ctx.fillStyle = "#aaccff";
    ctx.font = fontSize + "px monospace";
  
    for (let i = 0; i < matrixArray.length; i++){
        const text = chars.charAt(Math.floor(Math.random() * chars.length));
        //const text = chars.charAt(i % chars.length);
        ctx.fillText(text, i*fontSize, matrixArray[i]*fontSize);
      
        if (matrixArray[i]*fontSize > c.height && Math.random() > 0.975){
            matrixArray[i] = 0;
        }
        matrixArray[i]++;
    }
};

setInterval(rain, 100);


