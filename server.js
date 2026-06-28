import express from 'express';
import bodyParser from 'body-parser';
import path from 'path';
import { fileURLToPath } from 'url';
import Razorpay from 'razorpay';
import crypto from 'crypto';
import dotenv from 'dotenv';
import rateLimit from 'express-rate-limit';
import jwt from 'jsonwebtoken';
import helmet from 'helmet';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
import { Resend } from 'resend';

// ============================================================
// SECURITY: Helmet middleware — security headers
// ============================================================
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" },
  contentSecurityPolicy: false, // Disabled for Razorpay scripts to load
}));

// ============================================================
// SECURITY: Rate limiting
// ============================================================
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: { success: false, message: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Stricter limit for auth attempts
  message: { success: false, message: 'Too many login attempts, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const contactLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // 5 contact messages per hour per IP
  message: { success: false, message: 'Too many messages sent. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const orderLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 20, // 20 order emails per hour per IP
  message: { success: false, message: 'Too many orders. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(generalLimiter);

// ============================================================
// SECURITY: Input sanitization helper
// ============================================================
const sanitizeInput = (input) => {
  if (typeof input === 'string') {
    return input
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/\//g, '&#x2F;')
      .trim();
  }
  return input;
};

const sanitizeObject = (obj) => {
  if (typeof obj !== 'object' || obj === null) return obj;
  const sanitized = Array.isArray(obj) ? [] : {};
  for (const [key, value] of Object.entries(obj)) {
    sanitized[key] = typeof value === 'string' ? sanitizeInput(value) : value;
  }
  return sanitized;
};

// Resend — HTTP email API (reliable from cloud hosts, unlike SMTP)
// Free tier: 100 emails/day. Sign up at https://resend.com
const resend = process.env.RESEND_API_KEY
  ? new Resend(process.env.RESEND_API_KEY)
  : null;

const FROM_EMAIL = process.env.RESEND_FROM_EMAIL || 'onboarding@resend.dev';

// Initialize Razorpay (server-side only — live key never exposed to frontend)
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// SECURITY: JWT secret (from env or auto-generated)
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'murali_admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'MuraliIceCream@2025';

// CORS Middleware
app.use((req, res, next) => {
  const allowedOrigins = [
    'https://whitesmoke-squirrel-325874.hostingersite.com',
    'https://muraliicecream.org',
    'https://muraliicecream.com',
    'https://muraliicecream.onrender.com',
    'http://localhost:5173',
    'http://localhost:3000',
    'https://localhost:5173'
  ];

  const origin = req.headers.origin;

  if (origin && allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  } else if (!origin) {
    res.setHeader('Access-Control-Allow-Origin', '*');
  }

  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Max-Age', '86400');

  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  next();
});

// Middleware
app.use(bodyParser.json({ limit: '10kb' })); // SECURITY: Limit body size

// Note: Frontend is hosted on Hostinger — Render is API-only.
// No static file serving needed here.

// ============================================================
// SECURITY: Admin Authentication — JWT-based
// ============================================================
app.post('/api/auth/login', authLimiter, (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ success: false, message: 'Username and password are required' });
  }

  const sanitizedUsername = sanitizeInput(username);

  if (sanitizedUsername === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
    // Create JWT token (8 hour expiry)
    const token = jwt.sign(
      { username: sanitizedUsername, role: 'admin' },
      JWT_SECRET,
      { expiresIn: '8h' }
    );

    return res.json({
      success: true,
      token,
      expiresIn: 8 * 60 * 60 * 1000 // 8 hours in ms
    });
  }

  return res.status(401).json({ success: false, message: 'Invalid credentials' });
});

// SECURITY: Verify JWT middleware
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'Authentication required' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ success: false, message: 'Invalid or expired token' });
  }
};

// Verify token endpoint (for session validation)
app.get('/api/auth/verify', verifyToken, (req, res) => {
  res.json({ success: true, user: req.user });
});

// Payment endpoint for Google Pay
app.post('/api/pay', (req, res) => {
  const { amount, currency, paymentMethod } = req.body;

  if (!amount || !currency || !paymentMethod) {
    return res.status(400).json({ success: false, message: 'Missing required fields' });
  }

  console.log(`Processing payment of ${amount} ${currency} via ${paymentMethod}`);

  setTimeout(() => {
    res.json({
      success: true,
      message: 'Payment processed successfully!',
      transactionId: 'TXN_' + Math.random().toString(36).substr(2, 9).toUpperCase(),
      amount: amount,
      currency: currency
    });
  }, 2000);
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
      notes: (() => {
        const customer = orderData?.customerInfo || {};
        const items = orderData?.cartItems || [];

        const productSummary = items
          .map(item => `${item.quantity}x ${item.name}`)
          .join(', ') || 'N/A';

        const customerName = `${customer.firstName || ''} ${customer.lastName || ''}`.trim() || 'N/A';
        const address = [
          customer.address,
          customer.city,
          customer.state,
          customer.pincode
        ].filter(Boolean).join(', ') || 'N/A';

        return {
          customer_name: customerName,
          products: productSummary,
          delivery_address: address,
          phone: customer.phone || 'N/A',
        };
      })()
    };

    const order = await razorpay.orders.create(options);

    res.json({
      success: true,
      order,
      key_id: process.env.RAZORPAY_KEY_ID // SECURITY: Only key_id is sent — never key_secret
    });
  } catch (error) {
    console.error('Error creating Razorpay order:', error);
    res.status(500).json({
      success: false,
      message: 'Error creating order',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
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

    // Verify signature — SECURITY: This ensures payment was actually processed by Razorpay
    const body = razorpay_order_id + '|' + razorpay_payment_id;
    const expectedSignature = crypto
      .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
      .update(body.toString())
      .digest('hex');

    const isAuthentic = expectedSignature === razorpay_signature;

    if (isAuthentic) {
      console.log('Payment verified successfully:', {
        order_id: razorpay_order_id,
        payment_id: razorpay_payment_id,
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
        message: 'Payment verification failed — signature mismatch'
      });
    }
  } catch (error) {
    console.error('Error verifying payment:', error);
    res.status(500).json({
      success: false,
      message: 'Error verifying payment',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
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
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

// Send Contact Form Email
app.post('/api/send-contact-email', contactLimiter, async (req, res) => {
  try {
    // SECURITY: Sanitize all inputs
    const sanitizedBody = sanitizeObject(req.body);
    const { name, email, phone, subject, message } = sanitizedBody;

    if (!email || !name || !message) {
      return res.status(400).json({ success: false, message: 'Missing required fields' });
    }

    const adminEmailHtml = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; border: 1px solid #e0e0e0; border-radius: 8px; overflow: hidden;">
        <div style="background-color: #ff4d4d; padding: 20px; text-align: center; color: white;">
          <h1 style="margin: 0;">Murali Icecream</h1>
          <p style="margin: 5px 0 0;">New Contact Form Submission</p>
        </div>
        <div style="padding: 20px;">
          <div style="background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0;">
            <p style="margin: 5px 0;"><strong>Name:</strong> ${name}</p>
            <p style="margin: 5px 0;"><strong>Email:</strong> ${email}</p>
            <p style="margin: 5px 0;"><strong>Phone:</strong> ${phone || 'Not provided'}</p>
            <p style="margin: 5px 0;"><strong>Subject:</strong> ${subject}</p>
            <p style="margin: 5px 0;"><strong>Date:</strong> ${new Date().toLocaleString()}</p>
          </div>
          <h3>Message:</h3>
          <div style="background-color: #ffffff; padding: 15px; border-left: 4px solid #ff4d4d; margin: 10px 0;">
            <p style="white-space: pre-wrap;">${message}</p>
          </div>
        </div>
      </div>
    `;

    const customerEmailHtml = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; border: 1px solid #e0e0e0; border-radius: 8px; overflow: hidden;">
        <div style="background-color: #ff4d4d; padding: 20px; text-align: center; color: white;">
          <h1 style="margin: 0;">Murali Icecream</h1>
          <p style="margin: 5px 0 0;">Thank You for Contacting Us!</p>
        </div>
        <div style="padding: 20px;">
          <p>Dear ${name},</p>
          <p>Thank you for reaching out to us! We have received your message and our team will get back to you as soon as possible.</p>
          <div style="background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0;">
            <h3 style="margin-top: 0;">Your Message Summary:</h3>
            <p style="margin: 5px 0;"><strong>Subject:</strong> ${subject}</p>
            <p style="margin: 5px 0;"><strong>Message:</strong></p>
            <div style="background-color: #ffffff; padding: 10px; border-left: 3px solid #ff4d4d; margin-top: 10px;">
              <p style="white-space: pre-wrap; margin: 0;">${message}</p>
            </div>
          </div>
          <p>We typically respond within 24 hours during business hours.</p>
          <p>Best regards,<br><strong>Murali Icecream Team</strong></p>
        </div>
      </div>
    `;

    if (!resend) {
      console.warn('Resend not configured — email not sent');
      return res.json({ success: true, message: 'Message received (email skipped — no API key)' });
    }

    const customerMsg = {
      from: `Murali Icecream <${FROM_EMAIL}>`,
      to: email,
      subject: 'Thank you for contacting Murali Icecream',
      html: customerEmailHtml,
    };

    const adminMsg = {
      from: `Murali Icecream Website <${FROM_EMAIL}>`,
      to: 'muralicecream@gmail.com',
      subject: `New Contact Form: ${subject} - ${name}`,
      html: adminEmailHtml,
      replyTo: email,
    };

    // Send both emails in parallel
    const contactResults = await Promise.allSettled([
      resend.emails.send(customerMsg),
      resend.emails.send(adminMsg),
    ]);

    if (contactResults[0].status === 'rejected') {
      console.error('Error sending customer confirmation email:', contactResults[0].reason);
    }
    if (contactResults[1].status === 'rejected') {
      console.error('Error sending admin notification email:', contactResults[1].reason);
    }

    res.json({ success: true, message: 'Your message has been sent successfully! We will get back to you soon.' });

  } catch (error) {
    console.error('Error processing contact form:', error);
    res.status(500).json({ success: false, message: 'Failed to send message. Please try again later.' });
  }
});

// Send Order Email
app.post('/api/send-order-email', orderLimiter, async (req, res) => {
  try {
    // SECURITY: Sanitize all inputs
    const orderDetails = sanitizeObject(req.body);

    const {
      orderId, firstName, lastName, email, phone,
      address, city, state, pincode,
      cartItems, addons, totalAmount,
      paymentMethod
    } = orderDetails;

    if (!email) {
      return res.status(400).json({ success: false, message: 'Missing email address' });
    }

    const itemsHtml = Array.isArray(cartItems) ? cartItems.map(item => `
      <tr>
        <td style="padding: 10px; border-bottom: 1px solid #eee;">${item.name} x ${item.quantity}</td>
        <td style="padding: 10px; border-bottom: 1px solid #eee; text-align: right;">₹${(item.price * item.quantity).toFixed(2)}</td>
      </tr>
    `).join('') : '<tr><td colspan="2">No items found</td></tr>';

    const addonsHtml = addons && typeof addons === 'object' && !Array.isArray(addons) ? '' : '';

    const emailHtml = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; border: 1px solid #e0e0e0; border-radius: 8px; overflow: hidden;">
        <div style="background-color: #ff4d4d; padding: 20px; text-align: center; color: white;">
          <h1 style="margin: 0;">Murali Icecream</h1>
          <p style="margin: 5px 0 0;">Order Confirmation</p>
        </div>
        <div style="padding: 20px;">
          <p>Dear ${firstName} ${lastName},</p>
          <p>Thank you for your order!</p>
          <div style="background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0;">
            <p style="margin: 5px 0;"><strong>Order ID:</strong> ${orderId}</p>
            <p style="margin: 5px 0;"><strong>Date:</strong> ${new Date().toLocaleString()}</p>
            <p style="margin: 5px 0;"><strong>Payment Method:</strong> ${paymentMethod === 'cod' ? 'Cash on Delivery' : 'Online Payment'}</p>
          </div>
          <h3>Order Details</h3>
          <table style="width: 100%; border-collapse: collapse;">
            <tr style="background-color: #eee;">
              <th style="padding: 10px; text-align: left;">Item</th>
              <th style="padding: 10px; text-align: right;">Price</th>
            </tr>
            ${itemsHtml}
            ${addonsHtml}
            <tr>
              <td style="padding: 10px; border-top: 2px solid #333; font-weight: bold;">Total Amount</td>
              <td style="padding: 10px; border-top: 2px solid #333; text-align: right; font-weight: bold;">₹${Number(totalAmount).toFixed(2)}</td>
            </tr>
          </table>
          <div style="margin-top: 20px; border-top: 1px solid #eee; padding-top: 20px;">
            <h3>Delivery Details</h3>
            <p>${address}</p>
            <p>${city}, ${state} - ${pincode}</p>
            <p>Phone: ${phone}</p>
          </div>
        </div>
      </div>
    `;

    if (!resend) {
      console.warn('Resend not configured — order email skipped');
      return res.json({ success: true, message: 'Order placed (email skipped — no API key)' });
    }

    const customerMsg = {
      from: `Murali Icecream <${FROM_EMAIL}>`,
      to: email,
      subject: `Order Confirmation - ${orderId}`,
      html: emailHtml,
    };

    const adminMsg = {
      from: `Murali Icecream System <${FROM_EMAIL}>`,
      to: 'muralicecream@gmail.com',
      subject: `New Order Alert: ${orderId} - ₹${Number(totalAmount).toFixed(2)}`,
      html: `
        <div style="background-color: #fff0f0; padding: 10px; margin-bottom: 20px; text-align: center; border: 1px solid red; color: #cc0000; border-radius: 4px;">
          <strong>ADMIN NOTIFICATION: New Order Received</strong>
        </div>
        ${emailHtml}
      `,
    };

    // Send both emails in parallel
    const results = await Promise.allSettled([
      resend.emails.send(customerMsg),
      resend.emails.send(adminMsg),
    ]);

    if (results[0].status === 'rejected') {
      console.error('Error sending customer email:', results[0].reason);
    }
    if (results[1].status === 'rejected') {
      console.error('Error sending admin email:', results[1].reason);
    }

    res.json({ success: true, message: 'Order confirmation emails sent successfully' });

  } catch (error) {
    console.error('Error sending order email:', error);
    res.status(500).json({ success: false, message: 'Failed to send order confirmation email' });
  }
});

// Frontend is served by Hostinger — no catchall route needed.

// Start the server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
