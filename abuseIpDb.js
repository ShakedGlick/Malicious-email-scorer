const axios = require("axios");

async function run() {
    try {
        const response = await axios.get("https://api.abuseipdb.com/api/v2/check", {
            params: {
                ipAddress: "127.0.0.1",
                maxAgeInDays: 90
            },
            headers: {
                Key: "589898d384a54f6d131767c0c054d3a95ee2b5f67d3bb9cf8188da84774981fb59d7a3a119044c12",
                Accept: "application/json"
            }
        });

        console.log(response.data);

    } catch (err) {
        console.log(err.response?.data || err.message);
    }
}

run();

