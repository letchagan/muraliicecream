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
import { createTransport } from 'nodemailer';

// Email Transporter
const transporter = createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Initialize Razorpay
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// CORS Middleware - Allow requests from your domains
app.use((req, res, next) => {
  // Allow requests from your domains
  const allowedOrigins = [
    'https://whitesmoke-squirrel-325874.hostingersite.com', // Your current Hostinger domain
    'https://muraliicecream.org', // Your custom domain
    'https://muraliicecream.onrender.com', // Your Render deployment
    'http://localhost:5173',
    'http://localhost:3000',
    'https://localhost:5173'
  ];

  const origin = req.headers.origin;

  // For production, allow all origins to avoid CORS issues
  // In production, you might want to be more restrictive
  if (process.env.NODE_ENV === 'production') {
    res.setHeader('Access-Control-Allow-Origin', '*');
  } else if (origin && allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  } else if (!origin) {
    // If no origin (e.g., direct access), allow it
    res.setHeader('Access-Control-Allow-Origin', '*');
  }

  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Max-Age', '86400'); // 24 hours

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

// Send Contact Form Email
app.post('/api/send-contact-email', async (req, res) => {
  console.log('Received contact form submission');
  try {
    const { name, email, phone, subject, message } = req.body;
    console.log('Contact form data:', { name, email, phone, subject, message });

    if (!email || !name || !message) {
      console.error('Missing required fields in contact form');
      return res.status(400).json({ success: false, message: 'Missing required fields' });
    }

    // Email to Admin (Notification)
    const adminEmailHtml = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; border: 1px solid #e0e0e0; border-radius: 8px; overflow: hidden;">
        <div style="background-color: #ff4d4d; padding: 20px; text-align: center; color: white;">
          <h1 style="margin: 0;">Murali Icecream</h1>
          <p style="margin: 5px 0 0;">New Contact Form Submission</p>
        </div>
        
        <div style="padding: 20px;">
          <div style="background-color: #fff0f0; padding: 10px; margin-bottom: 20px; text-align: center; border: 1px solid red; color: #cc0000; border-radius: 4px;">
            <strong>🔔 NEW MESSAGE FROM WEBSITE CONTACT FORM</strong>
          </div>

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

          <div style="margin-top: 20px; padding: 15px; background-color: #f9f9f9; border-radius: 5px;">
            <p style="margin: 5px 0; font-size: 14px;"><strong>Reply to customer:</strong></p>
            <p style="margin: 5px 0; font-size: 14px;">Email: <a href="mailto:${email}">${email}</a></p>
            ${phone ? `<p style="margin: 5px 0; font-size: 14px;">Phone: <a href="tel:${phone}">${phone}</a></p>` : ''}
          </div>
        </div>
      </div>
    `;

    // Email to Customer (Confirmation)
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

          <div style="background-color: #fff9e6; padding: 15px; border-radius: 5px; margin: 20px 0;">
            <p style="margin: 5px 0;"><strong>📞 Contact Information:</strong></p>
            <p style="margin: 5px 0;">Phone: +91 8122262701, +91 9840660101</p>
            <p style="margin: 5px 0;">Email: muralicecream@gmail.com</p>
            <p style="margin: 5px 0;">Address: No 67, railway station, near Nemilicheri, Thiruninravur, Chennai, Tamil Nadu 602024</p>
          </div>

          <p>We typically respond within 24 hours during business hours.</p>
          <p>Best regards,<br><strong>Murali Icecream Team</strong></p>
          
          <div style="margin-top: 30px; text-align: center; font-size: 12px; color: #888;">
            <p>If you have any urgent queries, please call us at +91 8122262701</p>
            <p>&copy; ${new Date().getFullYear()} Murali Icecream. All rights reserved.</p>
          </div>
        </div>
      </div>
    `;

    // Send email to Admin
    const adminMailOptions = {
      from: `Murali Icecream Website <${process.env.EMAIL_USER}>`,
      to: 'muralicecream@gmail.com',
      subject: `🔔 New Contact Form: ${subject} - ${name}`,
      html: adminEmailHtml,
      replyTo: email
    };

    // Send email to Customer
    const customerMailOptions = {
      from: `Murali Icecream <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Thank you for contacting Murali Icecream',
      html: customerEmailHtml
    };

    console.log(`Sending confirmation email to customer: ${email}`);
    try {
      await transporter.sendMail(customerMailOptions);
      console.log('Customer confirmation email sent successfully');
    } catch (error) {
      console.error('Error sending customer confirmation email:', error);
    }

    console.log(`Sending notification email to admin: muralicecream@gmail.com`);
    try {
      await transporter.sendMail(adminMailOptions);
      console.log('Admin notification email sent successfully');
    } catch (error) {
      console.error('Error sending admin notification email:', error);
    }

    console.log('Contact form email processing completed');
    res.json({ success: true, message: 'Your message has been sent successfully! We will get back to you soon.' });

  } catch (error) {
    console.error('Error processing contact form:', error);
    res.status(500).json({ success: false, message: 'Failed to send message. Please try again later.', error: error.message });
  }
});

// Send Order Email
app.post('/api/send-order-email', async (req, res) => {
  console.log('Received order email request');
  try {
    const orderDetails = req.body;
    console.log('Order Details received:', JSON.stringify(orderDetails, null, 2));

    const {
      orderId, firstName, lastName, email, phone,
      address, city, state, pincode,
      cartItems, addons, totalAmount,
      paymentMethod
    } = orderDetails;

    if (!email) {
      console.error('Missing customer email in order details');
      return res.status(400).json({ success: false, message: 'Missing email address' });
    }

    // Generate Items HTML - safely handle if cartItems is missing
    const itemsHtml = Array.isArray(cartItems) ? cartItems.map(item => `
      <tr>
        <td style="padding: 10px; border-bottom: 1px solid #eee;">${item.name} x ${item.quantity}</td>
        <td style="padding: 10px; border-bottom: 1px solid #eee; text-align: right;">₹${(item.price * item.quantity).toFixed(2)}</td>
      </tr>
    `).join('') : '<tr><td colspan="2">No items found</td></tr>';

    // Generate Addons HTML
    const addonsHtml = addons && addons.length > 0 ? `
      <tr>
        <td colspan="2" style="padding: 10px; background-color: #f9f9f9; font-weight: bold;">Add-ons</td>
      </tr>
      ${addons.map(addon => `
        <tr>
          <td style="padding: 10px; border-bottom: 1px solid #eee;">${addon.name}</td>
          <td style="padding: 10px; border-bottom: 1px solid #eee; text-align: right;">₹${addon.price.toFixed(2)}</td>
        </tr>
      `).join('')}
    ` : '';

    const emailHtml = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; border: 1px solid #e0e0e0; border-radius: 8px; overflow: hidden;">
        <div style="background-color: #ff4d4d; padding: 20px; text-align: center; color: white;">
          <h1 style="margin: 0;">Murali Icecream</h1>
          <p style="margin: 5px 0 0;">Order Confirmation & Bill</p>
        </div>
        
        <div style="padding: 20px;">
          <p>Dear ${firstName} ${lastName},</p>
          <p>Thank you for your order! Here represents your official bill and order confirmation.</p>
          
          <div style="background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0;">
            <p style="margin: 5px 0;"><strong>Order ID:</strong> ${orderId}</p>
            <p style="margin: 5px 0;"><strong>Date:</strong> ${new Date().toLocaleString()}</p>
            <p style="margin: 5px 0;"><strong>Payment Method:</strong> ${paymentMethod === 'cod' ? 'Cash on Delivery' : 'Online Payment'}</p>
            <p style="margin: 5px 0;"><strong>Payment Status:</strong> ${paymentMethod === 'cod' ? '<span style="color: orange;">Pending (Pay on Delivery)</span>' : '<span style="color: green;">PAID</span>'}</p>
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
          
          <div style="margin-top: 30px; text-align: center; font-size: 12px; color: #888;">
            <p>If you have any questions, please contact us at muralicecream@gmail.com</p>
            <p>&copy; ${new Date().getFullYear()} Murali Icecream. All rights reserved.</p>
          </div>
        </div>
      </div>
    `;

    // Send email to Customer
    const customerMailOptions = {
      from: `Murali Icecream <${process.env.EMAIL_USER}>`,
      to: email,
      subject: `Order Confirmation - ${orderId}`,
      html: emailHtml
    };

    // Send email to Admin
    const adminMailOptions = {
      from: `Murali Icecream System <${process.env.EMAIL_USER}>`,
      to: 'muralicecream@gmail.com',
      subject: `New Order Alert: ${orderId} - ₹${Number(totalAmount).toFixed(2)}`,
      html: `
        <div style="background-color: #fff0f0; padding: 10px; margin-bottom: 20px; text-align: center; border: 1px solid red; color: #cc0000; border-radius: 4px;">
          <strong>🔔 ADMIN NOTIFICATION: New Order Received</strong>
        </div>
        ${emailHtml}
      `
    };

    console.log(`Sending email to customer: ${email}`);
    try {
      await transporter.sendMail(customerMailOptions);
      console.log('Customer email sent successfully');
    } catch (error) {
      console.error('Error sending customer email:', error);
      // Continue to try sending admin email even if customer email fails
    }

    console.log(`Sending email to admin: muralicecream@gmail.com`);
    try {
      await transporter.sendMail(adminMailOptions);
      console.log('Admin email sent successfully');
    } catch (error) {
      console.error('Error sending admin email:', error);
    }

    console.log(`Order email processing completed`);
    res.json({ success: true, message: 'Email sent successfully' });

  } catch (error) {
    console.error('Error sending email:', error);
    res.status(500).json({ success: false, message: 'Failed to send email', error: error.message });
  }
});

// The "catchall" handler: for any request that doesn't
// match one above, send back React's index.html file.
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'dist/index.html'));
});

// Start the server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
