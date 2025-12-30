// emailService.js — IAM-secure (NO Lambda URL)

const { LambdaClient, InvokeCommand } = require("@aws-sdk/client-lambda");

const client = new LambdaClient({
  region: "eu-west-1", // Ireland
});

async function sendEmail({ to, subject, message }) {
  const payload = { to, subject, message };

  try {
    const command = new InvokeCommand({
      FunctionName: "taskboard-email", 
      Payload: Buffer.from(JSON.stringify(payload)),
    });

    const response = await client.send(command);

    const result = JSON.parse(
      Buffer.from(response.Payload).toString()
    );

    console.log("📨 Lambda email response:", result);
    return result;
  } catch (err) {
    console.error("❌ Email Lambda Error:", err);
    return null;
  }
}

module.exports = { sendEmail };
