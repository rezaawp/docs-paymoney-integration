
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

### 3. Example Code
```php
<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use App\Models\MerchantApp;

class MockAppController extends Controller
{
    public function index()
    {
        $orders = DB::table('mock_orders')->orderBy('id', 'desc')->get();
        return view('mock.checkout', compact('orders'));
    }

    public function initiatePayment(Request $request)
    {
        $amount = $request->amount;
        $paymentMethod = $request->payment_method;

        // 1. Create Mock Order
        $orderId = DB::table('mock_orders')->insertGetId([
            'amount' => $amount,
            'status' => 'created',
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        // 2. Get Credentials (For simulation, we pick the first merchant app or a specific one)
        // In a real scenario, these would be in the .env of the Client App
        $app = MerchantApp::first();

        if (!$app) {
            return back()->with('error', 'No Merchant App found to simulate connection.');
        }

        // 3. Call PayMoney API to Verify Client & Get Token
        // URL is internal localhost for simulation
        $baseUrl = "https://nana-provident-augustine.ngrok-free.dev";

        $responseToken = Http::post("$baseUrl/api/deposit/verify-client", [
            'client_id' => $app->client_id,
            'client_secret' => $app->client_secret,
        ]);

        if (!$responseToken->successful()) {
            return back()->with('error', 'Failed to get access token: ' . $responseToken->body());
        }

        $tokenData = $responseToken->json();
        if ($tokenData['status'] !== 'success') {
            return back()->with('error', 'Token error: ' . $tokenData['message']);
        }

        $accessToken = $tokenData['data']['access_token'];

        // 4. Call PayMoney API to Initiate Transaction
        $callbackUrl = "https://nana-provident-augustine.ngrok-free.dev/mock/callback"; // Route we will create

        $responseTrans = Http::withHeaders([
            'Authorization' => 'Bearer ' . $accessToken
        ])->post("$baseUrl/api/deposit/transaction-info", [
            'amount' => $amount,
            'currency' => $request->currency,
            'payment_method' => $paymentMethod,
            'successUrl' => url('mock/success'),
            'cancelUrl' => url('mock/cancel'),
            'callbackUrl' => $callbackUrl,
            'order_id' => $orderId, // Passing the order ID
        ]);

        if (!$responseTrans->successful()) {
            return back()->with('error', 'Failed to initiate transaction: ' . $responseTrans->body());
        }

        $transData = $responseTrans->json();

        // Update PayMoney Ref in Mock Order for tracking
        // Note: We are using 'uuid' from response which now corresponds to grant_id if we updated DepositApiController correctly, or we can use grant_id from transaction_info

        // Based on previous code: 
        // return response()->json([ ... 'transaction_info' => $res ])
        // $res contains 'data' => ['grant_id' => ...]

        $grantId = $transData['transaction_info']['data']['grant_id'] ?? null;

        DB::table('mock_orders')->where('id', $orderId)->update([
            'paymoney_ref' => $grantId
        ]);

        // 5. Redirect User
        return redirect($transData['checkout_url']);
    }

    public function handleCallback(Request $request)
    {
        // This simulates the Client App receiving the webhook
        $paymoneyRef = $request->transaction_ref; // grant_id
        $status = $request->status;

        \Log::info("Mock App Callback Received", $request->all());

        // 1. Verify Signature (Anti-Cheating)
        $signature = $request->header('X-Signature');

        // In a real app, this secret would be stored in .env or config
        $app = MerchantApp::first();
        $clientSecret = $app ? $app->client_secret : '';

        if (!$signature) {
            \Log::warning("Mock App Callback Signature Missing", $request->all());
            return response()->json(['status' => 'error', 'message' => 'Missing Signature'], 403);
        }

        if ($signature) {
            $computedSignature = hash_hmac('sha256', json_encode($request->all()), $clientSecret);
            if (!hash_equals($computedSignature, $signature)) {
                \Log::warning("Mock App Callback Signature Mismatch", [
                    'received' => $signature,
                    'computed' => $computedSignature
                ]);
                return response()->json(['status' => 'error', 'message' => 'Invalid Signature'], 403);
            }
        }

        if ($paymoneyRef) {
            $mockStatus = 'pending';
            if ($status == 'success') {
                $mockStatus = 'paid';
            } elseif ($status == 'failed') {
                $mockStatus = 'failed';
            } elseif ($status == 'pending') {
                $mockStatus = 'pending';
            }

            \Log::info("Mock App Callback Status: " . $mockStatus);
            // $mockStatus = ($status == 'success') ? 'paid' : 'failed';
            // $mockStatus = ($status == 'pending') ? 'pending' : 'failed';

            // Idempotency: Check if order exists and current status
            $order = DB::table('mock_orders')
                ->where('paymoney_ref', $paymoneyRef)
                ->first();

            if ($order) {
                if ($order->status === 'paid') {
                    \Log::info("Mock App: Order {$paymoneyRef} already paid, skipping update.");
                    return response()->json(['status' => 'already_processed']);
                }

                // Conditional update
                DB::table('mock_orders')
                    ->where('paymoney_ref', $paymoneyRef)
                    ->where('status', '!=', 'paid')
                    ->update([
                        'status' => $mockStatus,
                        'updated_at' => now()
                    ]);
            }
        }

        return response()->json(['status' => 'received']);
    }

    public function refundTransaction(Request $request)
    {
        $grantId = $request->grant_id;
        $amount  = $request->amount;

        // 1. Get Credentials
        $app = MerchantApp::first();
        if (!$app) {
            return response()->json(['status' => 'error', 'message' => 'Merchant App not found'], 404);
        }

        // 2. Get Access Token
        $baseUrl = "https://nana-provident-augustine.ngrok-free.dev";

        $responseToken = Http::post("$baseUrl/api/deposit/verify-client", [
            'client_id' => $app->client_id,
            'client_secret' => $app->client_secret,
        ]);

        if (!$responseToken->successful()) {
            return response()->json(['status' => 'error', 'message' => 'Failed to auth: ' . $responseToken->body()], 400);
        }

        $accessToken = $responseToken->json()['data']['access_token'];

        // 3. Request Refund
        $responseRefund = Http::withHeaders([
            'Authorization' => 'Bearer ' . $accessToken
        ])->post("$baseUrl/api/refund/transaction", [
            'grant_id' => $grantId,
            'amount' => $amount
        ]);

        return $responseRefund->json();
    }
}
```

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
