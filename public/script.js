// script.js
const API_BASE = ""; // backend on same domain

document.addEventListener("DOMContentLoaded", () => {
  const optimizeBtn = document.getElementById("optimizeBtn");
  const previewCard = document.getElementById("previewCard");
  const previewContent = document.getElementById("previewContent");
  const downloadBtn = document.getElementById("downloadBtn");

  // ========= REAL GROQ OPTIMIZATION =========
  optimizeBtn.addEventListener("click", async () => {
    const fileInput = document.getElementById("file-upload");
    const jobUrl = document.getElementById("job-url").value;
    const email = document.getElementById("email").value;

    if (!fileInput.files.length) return alert("Please upload a CV file.");
    if (!jobUrl) return alert("Enter job URL.");
    if (!email) return alert("Enter your email.");

    const file = fileInput.files[0];

    previewCard.classList.remove("hidden");
    previewContent.innerHTML = `
      <p class="text-gray-500">Processing CV with AI… please wait.</p>
    `;

    try {
      // ========= STEP 1: Upload CV file =========
      const formData1 = new FormData();
      formData1.append("file", file);

      const uploadRes = await fetch(`/upload-cv`, {
        method: "POST",
        body: formData1,
      });

      const uploaded = await uploadRes.json();

      if (!uploaded.success) {
        previewContent.innerHTML = `<p class="text-red-600">File upload failed.</p>`;
        return;
      }

      // ========= STEP 2: Optimize with GROQ =========
      const response = await fetch(`/optimize-cv`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          filePath: uploaded.filePath,
          jobUrl: jobUrl,   // correct key
          email: email,
        }),
      });

      const data = await response.json();
      console.log("GROQ optimization response:", data);

      if (!data.success) {
        previewContent.innerHTML = `<p class="text-red-600">${data.message || "Optimization failed."}</p>`;
        return;
      }

      // ========= STEP 3: Render Preview =========
      if (!data.previewUrl) {
        previewContent.innerHTML = `
          <p class="text-red-600">Preview unavailable. Backend did not return previewUrl.</p>
        `;
        return;
      }

      previewContent.innerHTML = `
        <h3 class="font-bold text-lg mb-2">Optimized Preview</h3>

        <iframe 
          src="${data.previewUrl}" 
          class="w-full h-[600px] border rounded mb-4">
        </iframe>

        <a 
          href="${data.
