import express from "express";
import fetch from "node-fetch";
import cors from "cors";

const app = express();
const PORT = 3000;

// Enable CORS
app.use(cors());

// Root route
app.get("/", (req, res) => {
    res.send("Welcome to the Password Breach Checker API!");
});

// Proxy endpoint for HIBP
app.get("/pwned/:prefix", async (req, res) => {
    const { prefix } = req.params;
    try {
        const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
        if (!response.ok) {
            return res.status(response.status).send("Error fetching data from HIBP");
        }

        const data = await response.text();
        res.send(data);
    } catch (error) {
        console.error("Error:", error);
        res.status(500).send("Internal Server Error");
    }
});

// Start server
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
