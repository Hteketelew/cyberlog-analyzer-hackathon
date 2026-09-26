// ==========================================
// LOG ANALYZER
// ==========================================

async function analyze() {

  const fileInput = document.getElementById("file");
  const status = document.getElementById("status");

  const file = fileInput.files[0];

  if (!file) {

    status.innerHTML =
      '<span class="error">Please select a log file.</span>';

    return;
  }

  status.textContent = "Analyzing...";


  const formData = new FormData();

  formData.append("file", file);


  try {

    const response = await fetch(
      "/api/analyze",
      {
        method: "POST",
        body: formData
      }
    );


    const data = await response.json();


    if (!response.ok) {

      throw new Error(
        data.detail || "Analysis failed"
      );

    }


    // Show dashboard

    document.getElementById(
      "dashboard"
    ).style.display = "block";


    // Summary

    document.getElementById(
      "total"
    ).textContent = data.total_lines;


    document.getElementById(
      "critical"
    ).textContent = data.summary.critical;


    document.getElementById(
      "high"
    ).textContent = data.summary.high;


    document.getElementById(
      "medium"
    ).textContent = data.summary.medium;


    // Alerts

    const alertsElement =
      document.getElementById("alerts");


    if (data.alerts.length > 0) {

      alertsElement.innerHTML =
        data.alerts.map(
          function (alert) {

            return `
              <tr>

                <td class="${alert.severity.toLowerCase()}">
                  <b>${escapeHtml(alert.severity)}</b>
                </td>

                <td>
                  ${escapeHtml(alert.type)}
                </td>

                <td>
                  ${escapeHtml(alert.ip)}
                </td>

                <td>
                  ${escapeHtml(alert.message)}
                </td>

              </tr>
            `;

          }
        ).join("");

    }

    else {

      alertsElement.innerHTML = `
        <tr>
          <td colspan="4" class="ok">
            No suspicious activity detected.
          </td>
        </tr>
      `;

    }


    // Top IPs

    const ipsElement =
      document.getElementById("ips");


    if (data.top_ips.length > 0) {

      ipsElement.innerHTML =
        data.top_ips.map(
          function (item) {

            return `
              <span class="pill">
                ${escapeHtml(item.ip)}:
                ${item.count}
              </span>
            `;

          }
        ).join("");

    }

    else {

      ipsElement.textContent =
        "No IP addresses detected.";

    }


    status.innerHTML =
      `<span class="ok">
        Analysis complete: ${escapeHtml(data.filename)}
      </span>`;

  }


  catch (error) {

    status.innerHTML =
      `<span class="error">
        ${escapeHtml(error.message)}
      </span>`;

  }

}


// ==========================================
// AI CHAT
// ==========================================

async function sendMessage() {

  const input =
    document.getElementById("messageInput");

  const chatBox =
    document.getElementById("chatBox");

  const sendButton =
    document.getElementById("sendButton");


  const message =
    input.value.trim();


  if (!message) {
    return;
  }


  // Display user message

  const userMessage =
    document.createElement("div");

  userMessage.className =
    "user-message";

  userMessage.innerHTML =
    `<strong>You:</strong> ${escapeHtml(message)}`;

  chatBox.appendChild(userMessage);


  // Clear input

  input.value = "";


  // Disable button

  sendButton.disabled = true;

  sendButton.textContent =
    "Thinking...";


  // Loading message

  const loadingMessage =
    document.createElement("div");

  loadingMessage.className =
    "ai-message";

  loadingMessage.innerHTML =
    "<strong>AI:</strong> Thinking...";

  chatBox.appendChild(loadingMessage);


  chatBox.scrollTop =
    chatBox.scrollHeight;


  try {

    const response = await fetch(
      "/api/chat",
      {

        method: "POST",

        headers: {
          "Content-Type": "application/json"
        },

        body: JSON.stringify({
          message: message
        })

      }
    );


    const data =
      await response.json();


    // Remove loading

    loadingMessage.remove();


    if (data.reply) {

      const aiMessage =
        document.createElement("div");

      aiMessage.className =
        "ai-message";

      aiMessage.innerHTML =
        `<strong>AI:</strong><br>${escapeHtml(data.reply).replace(/\n/g, "<br>")}`;

      chatBox.appendChild(aiMessage);

    }

    else {

      const errorMessage =
        document.createElement("div");

      errorMessage.className =
        "error-message";

      errorMessage.innerHTML =
        `<strong>Error:</strong> ${escapeHtml(
          data.error || "Unknown error"
        )}`;

      chatBox.appendChild(errorMessage);

    }

  }


  catch (error) {

    loadingMessage.remove();


    const errorMessage =
      document.createElement("div");

    errorMessage.className =
      "error-message";

    errorMessage.innerHTML =
      "<strong>Error:</strong> Could not connect to the server.";

    chatBox.appendChild(errorMessage);


    console.error(error);

  }


  // Enable button

  sendButton.disabled = false;

  sendButton.textContent =
    "Send";


  chatBox.scrollTop =
    chatBox.scrollHeight;

}


// ==========================================
// ENTER KEY
// ==========================================

document
  .getElementById("messageInput")
  .addEventListener(
    "keydown",
    function (event) {

      if (event.key === "Enter") {

        sendMessage();

      }

    }
  );


// ==========================================
// HTML ESCAPING
// ==========================================

function escapeHtml(text) {

  const div =
    document.createElement("div");

  div.textContent =
    String(text);

  return div.innerHTML;
}
