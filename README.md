
# PayMoney Mock App & Payment Gateway Documentation

This repository contains the source code for the PayMoney Payment Gateway, including a **Mock App** to simulate merchant integration and payment flows.

## Mock App API

The Mock App (`App\Http\Controllers\MockAppController`) serves as a reference implementation for merchants integrating with PayMoney. It attempts to simulate the entire payment flow: from initiating a payment to handling asynchronous callbacks (webhooks).

### 1. Payment Initiation Flow

**Endpoint:** `POST /mock/initiate-payment`

This endpoint handles the form submission from the Mock Checkout page (`/mock/checkout`) and orchestrates the creation of a transaction.

**Process:**
1.  **Create Local Order**: Creates a record in the `mock_orders` table with status `created`.
2.  **Authentication**:
    *   Retrieves Client ID and Secret from the `merchant_apps` table.
    *   Calls `POST /api/deposit/verify-client` to obtain an **Access Token**.
3.  **Initiate Transaction**:
    *   Calls `POST /api/deposit/transaction-info` with the Access Token.
    *   Payload includes: `amount`, `currency`, `payment_method`, `successUrl`, `cancelUrl`, `callbackUrl` (Webhook URL), and `order_id` (Merchant's Order ID).
4.  **Redirect**:
    *   Receives a `checkout_url` from the API.
    *   Redirects the user to the PayMoney payment page.

### 2. Webhook / Callback Handler

**Endpoint:** `POST /mock/callback`

This endpoint acts as the merchant's webhook receiver. PayMoney sends a notification to this URL when a transaction status changes (e.g., Pending, Success, Failed).

**Security (Signature Verification):**
Requests are signed to prevent tampering.
- **Header:** `X-Signature`
- **Algorithm:** HMAC-SHA256
- **Content:** JSON Encoded Request Body
- **Secret:** Merchant Client Secret

**Verification Logic:**
```php
$computedSignature = hash_hmac('sha256', json_encode($request->all()), $clientSecret);
if (!hash_equals($computedSignature, $signature)) {
    // Reject Reqeust
}
```

**Payload:**
```json
{
    "status": "success", // or "pending", "failed"
    "amount": "10000.00",
    "currency": "IDR",
    "transaction_ref": "GRANT_ID_OR_UUID",
    "original_data": { ... } // Detailed gateway response
}
```

**Logic:**
- Finds the local order by `paymoney_ref`.
- Updates the local order status:
    - `success` -> `paid`
    - `pending` -> `pending`
    - Other -> `failed`
- **Idempotency**: Checks if the order is already `paid` to prevent double processing.

---

## Integration Guide

To integrate your application with PayMoney, follow these steps:

### 1. Initiate Payment

To start a transaction, make a server-to-server request to the PayMoney API.

1.  **Get Access Token:**
    *   Endpoint: `POST /api/deposit/verify-client`
    *   Body:
        ```json
        {
            "client_id": "YOUR_CLIENT_ID",
            "client_secret": "YOUR_CLIENT_SECRET"
        }
        ```
    *   Response: Returns an `access_token`.

2.  **Create Transaction:**
    *   Endpoint: `POST /api/deposit/transaction-info`
    *   Header: `Authorization: Bearer <access_token>`
    *   Body:
        ```json
        {
            "amount": "100.00",
            "currency": "USD",
            "payment_method": "stripe", // or midtrans, xendit, etc.
            "successUrl": "https://your-site.com/success",
            "cancelUrl": "https://your-site.com/cancel",
            "callbackUrl": "https://your-site.com/webhook",
            "order_id": "YOUR_UNIQUE_ORDER_ID"
        }
        ```
    *   **Response:** Returns a `checkout_url`. Redirect your user to this URL.

### 2. Handle Callback (Anti-Cheating Verification)

When the transaction is completed (or failed), PayMoney will send a POST request to your `callbackUrl`.
**Crucial:** You must verify the signature of this request to ensure it comes from PayMoney and hasn't been tampered with.

**Security Headers:**
- `X-Signature`: The HMAC-SHA256 signature of the request body.

#### PHP Example (Laravel/Native)

```php
<?php

$clientSecret = 'YOUR_CLIENT_SECRET'; // Store this securely!
$payload = file_get_contents('php://input');
$signature = $_SERVER['HTTP_X_SIGNATURE'] ?? '';

// 1. Verify Signature
$computedSignature = hash_hmac('sha256', $payload, $clientSecret);

if (!hash_equals($computedSignature, $signature)) {
    http_response_code(403);
    echo json_encode(['status' => 'error', 'message' => 'Invalid Signature']);
    exit;
}

// 2. Process Data
$data = json_decode($payload, true);

if ($data['status'] === 'success') {
    // Mark order as paid in your database
    // $orderId = $data['original_data']['order_id'];
}

echo json_encode(['status' => 'received']);
?>
```

#### Node.js Example (Express)

```javascript
const express = require('express');
const crypto = require('crypto');
const app = express();

// Use raw body parser to get exact payload for signature verification
app.use(express.json({
    verify: (req, res, buf) => {
        req.rawBody = buf;
    }
}));

const CLIENT_SECRET = 'YOUR_CLIENT_SECRET';

app.post('/webhook', (req, res) => {
    const signature = req.headers['x-signature'];
    const payload = req.rawBody; // Buffer matches php://input

    // 1. Verify Signature
    const computedSignature = crypto
        .createHmac('sha256', CLIENT_SECRET)
        .update(payload)
        .digest('hex');

    if (signature !== computedSignature) {
        console.error('Signature mismatch!');
        return res.status(403).json({ status: 'error', message: 'Invalid Signature' });
    }

    // 2. Process Data
    const data = req.body;
    console.log('Payment Status:', data.status);

    if (data.status === 'success') {
        // Update your database
    }

    res.json({ status: 'received' });
});

app.listen(3000, () => console.log('Server running on port 3000'));
```

#### Golang Example (Gin)

```go
package main

import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "io/ioutil"
    "net/http"

    "github.com/gin-gonic/gin"
)

const ClientSecret = "YOUR_CLIENT_SECRET"

func main() {
    r := gin.Default()

    r.POST("/webhook", func(c *gin.Context) {
        signature := c.GetHeader("X-Signature")
        
        // Read raw body for verification
        body, _ := ioutil.ReadAll(c.Request.Body)
        
        // 1. Verify Signature
        h := hmac.New(sha256.New, []byte(ClientSecret))
        h.Write(body)
        computedSignature := hex.EncodeToString(h.Sum(nil))

        if signature != computedSignature {
            c.JSON(http.StatusForbidden, gin.H{"status": "error", "message": "Invalid Signature"})
            return
        }

        // 2. Process Data
        var data map[string]interface{}
        if err := json.Unmarshal(body, &data); err != nil {
             c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON"})
             return
        }
        
        // Check status
        if status, ok := data["status"].(string); ok && status == "success" {
            // Update your database
        }

        c.JSON(http.StatusOK, gin.H{"status": "received"})
    })

    r.Run(":3000")
}
```

---

## Standard Laravel Documentation

<p align="center"><a href="https://laravel.com" target="_blank"><img src="https://raw.githubusercontent.com/laravel/art/master/logo-lockup/5%20SVG/2%20CMYK/1%20Full%20Color/laravel-logolockup-cmyk-red.svg" width="400"></a></p>

## About Laravel

Laravel is a web application framework with expressive, elegant syntax. We believe development must be an enjoyable and creative experience to be truly fulfilling. Laravel takes the pain out of development by easing common tasks used in many web projects, such as:

- [Simple, fast routing engine](https://laravel.com/docs/routing).
- [Powerful dependency injection container](https://laravel.com/docs/container).
- Multiple back-ends for [session](https://laravel.com/docs/session) and [cache](https://laravel.com/docs/cache) storage.
- Expressive, intuitive [database ORM](https://laravel.com/docs/eloquent).
- Database agnostic [schema migrations](https://laravel.com/docs/migrations).
- [Robust background job processing](https://laravel.com/docs/queues).
- [Real-time event broadcasting](https://laravel.com/docs/broadcasting).

Laravel is accessible, powerful, and provides tools required for large, robust applications.
