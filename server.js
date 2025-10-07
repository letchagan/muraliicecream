import express from 'express';
import express from 'express';
import bodyParser from 'body-parser';
import path from 'path';
import { fileURLToPath } from 'url';
import Razorpay from 'razorpay';
import crypto from 'crypto';
import dotenv from 'dotenv';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// Initialize Razorpay
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// CORS Middleware - Allow requests from your Hostinger domain
app.use((req, res, next) => {
  // Allow requests from your Hostinger domain and localhost
  const allowedOrigins = [
    'https://whitesmoke-squirrel-325874.hostingersite.com', // Your current Hostinger domain
    'https://yourdomain.com', // Add your custom domain when ready
    'http://localhost:5173',
    'http://localhost:3000',
    'https://localhost:5173'
  ];
  
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  
  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }
  
  next();
});

// Middleware
app.use(bodyParser.json());

// Serve static files from the React app build directory
app.use(express.static(path.join(__dirname, 'dist')));

// Serve robots.txt and sitemap.xml
app.get('/robots.txt', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'robots.txt'));
});

app.get('/sitemap.xml', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'sitemap.xml'));
});

// Payment endpoint for Google Pay
app.post('/api/pay', (req, res) => {
    const { amount, currency, paymentMethod } = req.body;

    // Validate the request
    if (!amount || !currency || !paymentMethod) {
        return res.status(400).json({ success: false, message: 'Missing required fields' });
    }

    // Here you would integrate Google Pay API to process the payment
    // For now, we will simulate a successful payment
    console.log(`Processing payment of ${amount} ${currency} via ${paymentMethod}`);

    // Simulate payment processing
    setTimeout(() => {
        res.json({ 
            success: true, 
            message: 'Payment processed successfully!',
            transactionId: 'TXN_' + Math.random().toString(36).substr(2, 9).toUpperCase(),
            amount: amount,
            currency: currency
        });
    }, 2000); // Simulate 2 seconds processing time
});

// Razorpay Payment Routes

// Create Razorpay Order
app.post('/api/payment/create-order', async (req, res) => {
  try {
    const { amount, currency = 'INR', receipt, orderData } = req.body;

    // Validate amount
    if (!amount || amount < 1) {
      return res.status(400).json({
        success: false,
        message: 'Invalid amount'
      });
    }

    const options = {
      amount: Math.round(amount * 100), // Convert to paise
      currency,
      receipt: receipt || `order_${Date.now()}`,
      notes: {
        orderData: JSON.stringify(orderData),
      }
    };

    const order = await razorpay.orders.create(options);
    
    res.json({
      success: true,
      order,
      key_id: process.env.RAZORPAY_KEY_ID
    });
  } catch (error) {
    console.error('Error creating Razorpay order:', error);
    res.status(500).json({
      success: false,
      message: 'Error creating order',
      error: error.message
    });
  }
});

// Verify Payment
app.post('/api/payment/verify', async (req, res) => {
  try {
    const {
      razorpay_order_id,
      razorpay_payment_id,
      razorpay_signature,
      orderData
    } = req.body;

    // Verify signature
    const body = razorpay_order_id + '|' + razorpay_payment_id;
    const expectedSignature = crypto
      .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
      .update(body.toString())
      .digest('hex');

    const isAuthentic = expectedSignature === razorpay_signature;

    if (isAuthentic) {
      // Payment verified successfully
      // Here you can save the order to your database
      console.log('Payment verified successfully:', {
        order_id: razorpay_order_id,
        payment_id: razorpay_payment_id,
        orderData
      });

      res.json({
        success: true,
        message: 'Payment verified successfully',
        payment_id: razorpay_payment_id,
        order_id: razorpay_order_id
      });
    } else {
      res.status(400).json({
        success: false,
        message: 'Payment verification failed'
      });
    }
  } catch (error) {
    console.error('Error verifying payment:', error);
    res.status(500).json({
      success: false,
      message: 'Error verifying payment',
      error: error.message
    });
  }
});

// Get Payment Status
app.get('/api/payment/status/:paymentId', async (req, res) => {
  try {
    const { paymentId } = req.params;
    const payment = await razorpay.payments.fetch(paymentId);
    
    res.json({
      success: true,
      payment
    });
  } catch (error) {
    console.error('Error fetching payment status:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching payment status',
      error: error.message
    });
  }
});

// The "catchall" handler: for any request that doesn't
// match one above, send back React's index.html file.
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'dist/index.html'));
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
