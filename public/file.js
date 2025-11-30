// public/file.js
document.addEventListener('DOMContentLoaded', function () {
  const fileInput = document.getElementById('file-upload');
  const uploadBtn = document.getElementById('upload-btn');
  const fileInfo = document.getElementById('file-info');
  const progressContainer = document.getElementById('progress-container');
  const progressBar = document.getElementById('upload-progress');
  const optimizeBtn = document.getElementById('optimize-btn');
  const previewCard = document.getElementById('previewCard');
  const previewContent = document.getElementById('previewContent');
  const jobInput = document.getElementById('job-link');
  const downloadBtn = document.getElementById('downloadBtn');
  const editBtn = document.getElementById('editBtn');

  let uploadedFilePath = null;
  let lastPdfFilename = null;

  const allowed = [
    "application/pdf",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "text/plain",
  ];

  // toast
  window.showToast = (msg, type = "success") => {
    const t = document.createElement("div");
    t.className = `fixed bottom-4 right-4 px-4 py-2 rounded shadow text-white z-50 ${
      type === "success" ? "bg-green-600" : "bg-red-600"
    }`;
    t.textContent = msg;
    document.body.appendChild(t);
    setTimeout(() => t.remove(), 3000);
  };

  // File selection
  fileInput?.addEventListener("change", (e) => {
    const f = e.target.files[0];
    if (!f) {
      fileInfo.textContent = "";
      return;
    }
    if (!allowed.includes(f.type) && !f.name.match(/\.(pdf|docx|doc|txt)$/i)) {
      showToast("Unsupported file type. Use PDF/DOCX/DOC/TXT", "error");
      fileInput.value = "";
      fileInfo.textContent = "";
      return;
    }
    const mb = (f.size / (1024 * 1024)).toFixed(2);
    fileInfo.textContent = `📄 ${f.name} (${mb} MB)`;
    uploadedFilePath = null;
    optimizeBtn.disabled = true;
  });

  // Upload file to server
  uploadBtn?.addEventListener("click", async () => {
    const f = fileInput.files[0];
    if (!f) return showToast("Please choose a file first.", "error");

    const form = new FormData();
    form.append("file", f);

    progressContainer.style.display = "block";
    progressBar.style.width = "0%";

    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/upload-cv", true);

    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) {
        const pct = Math.round((e.loaded / e.total) * 100);
        progressBar.style.width = pct + "%";
      }
    };

    xhr.onload = () => {
      if (xhr.status === 200) {
        const resp = JSON.parse(xhr.responseText);
        if (resp.success) {
          showToast("File uploaded ✔️", "success");
          uploadedFilePath = resp.filePath;
          optimizeBtn.disabled = false;
        } else {
          showToast(resp.message || "Upload failed", "error");
        }
      } else {
        showToast("Server upload error", "error");
      }
    };

    xhr.onerror = () => showToast("Network error during upload", "error");
    xhr.send(form);
  });

  // Optimize CV
  optimizeBtn?.addEventListener("click", async (e) => {
    e.preventDefault();
    if (!uploadedFilePath) return showToast("Upload a file first", "error");

    const jobURL = jobInput?.value || "";
    if (!jobURL) return showToast("Please paste the job posting URL", "error");

    optimizeBtn.disabled = true;
    optimizeBtn.textContent = "Generating preview…";

    try {
      const resp = await fetch("/optimize-cv", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ filePath: uploadedFilePath, jobURL }),
      });

      const data = await resp.json();
      if (!data.success) throw new Error(data.message || "Optimization failed");

      lastPdfFilename = data.pdfFilename;

      // clean preview UI (no email button)
      previewContent.innerHTML = `
        <div class="mb-4">
          <a href="${data.downloadUrl}" 
             target="_blank"
             class="inline-flex items-center px-4 py-2 bg-green-600 text-white rounded shadow hover:bg-green-700">
             Download Optimized PDF
          </a>
        </div>

        <iframe src="${data.previewUrl}"
          style="width:100%;height:650px;border:1px solid #e5e7eb;border-radius:8px">
        </iframe>
      `;

      previewCard.classList.remove("hidden");
      previewCard.scrollIntoView({ behavior: "smooth" });

      showToast("Preview ready!", "success");
    } catch (err) {
      console.error(err);
      showToast(err.message || "Error generating preview", "error");
    } finally {
      optimizeBtn.disabled = false;
      optimizeBtn.textContent = "Optimize my CV (preview)";
    }
  });

  // Edit button
  editBtn?.addEventListener("click", () => {
    fileInput?.scrollIntoView({ behavior: "smooth" });
  });

  // Download button
  downloadBtn?.addEventListener("click", () => {
    if (!lastPdfFilename) return showToast("No generated PDF yet", "error");
    window.open(`/download?file=${encodeURIComponent(lastPdfFilename)}`, "_blank");
  });
});
