console.log("Script loaded");

const fileInput = document.getElementById('fileInput');
fileInput?.addEventListener('change', () => {
  if (fileInput.files && fileInput.files.length > 0) {
    console.log(`File added: ${fileInput.files[0].name}`);
  } else {
    console.log(`No file selected`);
  }
});
