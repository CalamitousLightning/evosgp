console.log("✅ EVOSGPT script.js loaded.");

// Sidebar toggle
function toggleSidebar() {
  const sidebar = document.getElementById("sidebar");
  const overlay = document.getElementById("overlay");
  sidebar.classList.toggle("active");
  overlay.classList.toggle("active");
}

// Hub dropdown toggle
function toggleHub() {
  const hub = document.getElementById("hub");
  hub.style.display = hub.style.display === "block" ? "none" : "block";
}

const chatBox = document.getElementById("chat-box");
function scrollToBottom() {
  chatBox.scrollTop = chatBox.scrollHeight;
}

// 🌗 Theme toggle
const themeToggle = document.getElementById("theme-toggle");
if (themeToggle) {
  themeToggle.addEventListener("click", () => {
    const current = document.body.getAttribute("data-theme");
    const newTheme = current === "dark" ? "light" : "dark";
    document.body.setAttribute("data-theme", newTheme);
    themeToggle.textContent = newTheme === "dark" ? "☀" : "🌙";
    localStorage.setItem("theme", newTheme);
  });

  const savedTheme = localStorage.getItem("theme");
  if (savedTheme) {
    document.body.setAttribute("data-theme", savedTheme);
    themeToggle.textContent = savedTheme === "dark" ? "☀" : "🌙";
  }
}

// ✅ Markdown rendering
function safeMarkdown(txt) {
  try {
    if (!window.marked) {
      console.error("❌ Marked.js not loaded!");
      return txt;
    }
    const html = marked.parse(txt);
    if (window.hljs) setTimeout(() => hljs.highlightAll(), 0);
    return html;
  } catch (e) {
    console.error("Markdown parse error", e);
    return txt;
  }
}

// 💬 Chat form logic
const form = document.getElementById("chat-form");
if (form) {
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const input = document.getElementById("message");
    const text = input.value.trim();
    if (!text) return;

    chatBox.insertAdjacentHTML("beforeend", `<div class="msg user">${text}</div>`);
    scrollToBottom();
    input.value = "";

    const typing = document.createElement("div");
    typing.className = "msg bot";
    typing.id = "typing-bubble";
    typing.innerHTML = "EVOSGPT is typing...";
    chatBox.appendChild(typing);
    scrollToBottom();

    try {
      const res = await fetch("/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: text })
      });
      if (!res.ok) throw new Error("Network error " + res.status);
      const data = await res.json();
      typing.remove();

      chatBox.insertAdjacentHTML("beforeend", `
        <div class="msg bot">
          <strong>EVOSGPT [${data.tier || "?"}]</strong><br>
          <div class="bot-content">${safeMarkdown(data.reply)}</div>
          <button class="copy-btn" onclick="copyText(this)">📋</button>
        </div>
      `);
      scrollToBottom();
    } catch (err) {
      typing.remove();
      chatBox.insertAdjacentHTML("beforeend", `<div class="msg bot error">⚠ ${err.message}</div>`);
    }
  });
}

// 📋 Copy text
function copyText(button) {
  const text = button.parentElement.innerText.replace("📋", "").trim();
  navigator.clipboard.writeText(text).then(() => {
    button.textContent = "✅";
    setTimeout(() => (button.textContent = "📋"), 1500);
  });
}

// 🪄 Referral link copy
function copyReferral() {
  const link = document.getElementById("referral-link");
  if (!link) return;
  link.select();
  navigator.clipboard.writeText(link.value).then(() => alert("✅ Referral link copied!"));
}

// 🔔 System notices
async function loadNotices() {
  try {
    const res = await fetch("/system_notices");
    if (!res.ok) return;
    const data = await res.json();
    const container = document.getElementById("system-notices");
    if (!container) return;

    container.innerHTML = "<h3>📢 System Notices</h3>";
    if (data.length === 0) {
      container.innerHTML += '<div class="notice info">No active notices.</div>';
    } else {
      data.forEach(note => {
        container.innerHTML += `<div class="notice ${note.type}">${note.msg}</div>`;
      });
    }
  } catch {}
}
loadNotices();
setInterval(loadNotices, 30000);
