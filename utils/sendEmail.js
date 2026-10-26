import fetch from "node-fetch";

export async function sendEmail(to, subject, message) {
  try {
    const res = await fetch(process.env.EMAIL_LAMBDA_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ to, subject, message })
    });

    const data = await res.json();
    console.log("Lambda email result:", data);
  } catch (err) {
    console.error("Email Lambda error:", err);
  }
}
