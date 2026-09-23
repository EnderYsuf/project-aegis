console.log("Script loaded"); // debug
// elements
const fileInput = document.getElementById('fileInput');
const aiActionsWindow = document.getElementById('aiActionsWindow');
const uploadWrapper = document.getElementById('uploadWrapper');

// some debug stuff for fun
const ai_thinking_quotes = [
  "thinking...",
  "Thinking more...",
  "Thinking even more...",
  "Should I tell you I'm thinking?",
  "Ooh, I'm soo thinking",
  "I'm AI and I think",
  "Uuu, what is this? Is that thinking?"
];

// check for file debug only for now
fileInput?.addEventListener('change', () => {
  if (fileInput.files && fileInput.files.length > 0) {
    console.log(`File added: ${fileInput.files[0].name}`);
  } else {
    console.log(`No file selected`);
  }
});

// ai actions check function
function ai_window_test() {
  // adding random stuff into window as if ai is thinking
  setTimeout(() => {
    aiActionsWindow.innerHTML = "";
    uploadWrapper.classList.add("hidden");
    aiActionsWindow.classList.remove("hidden");
  }, 2000);

  let interval = setInterval(() => {
    aiActionsWindow.innerHTML += ai_thinking_quotes[Math.floor(Math.random() * ai_thinking_quotes.length)] + "\n";
  }, 1000);
}
