(function () {
  const box = document.querySelector(".chatbox");
  if (!box) return;
  const messages = box.querySelector(".chat-messages");
  const form = box.querySelector("form");
  const input = form.querySelector("input");
  const reportId = box.dataset.reportId || "";
  function addMessage(text, className) {
    const item = document.createElement("div");
    item.className = "chat-message " + className;
    item.textContent = text;
    messages.appendChild(item);
    messages.scrollTop = messages.scrollHeight;
  }
  form.addEventListener("submit", async function (event) {
    event.preventDefault();
    const question = input.value.trim();
    if (!question) return;
    addMessage(question, "chat-user");
    input.value = "";
    try {
      const response = await fetch("/chat", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({question: question, report_id: reportId})
      });
      const body = await response.json();
      if (!response.ok) throw new Error(body.answer || "Chat unavailable");
      addMessage(body.answer, "chat-assistant");
    } catch (error) {
      addMessage(error.message, "chat-error");
    }
  });
})();
