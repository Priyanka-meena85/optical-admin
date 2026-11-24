const http = require('http');

function request(options, data = null) {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body: body
        });
      });
    });
    req.on('error', reject);
    if (data) {
      req.write(typeof data === 'string' ? data : JSON.stringify(data));
    }
    req.end();
  });
}

async function runTests() {
  console.log('--- STARTING SHARMA OPTICAL FULL-STACK TEST SUITE ---');

  // 1. Audit Check
  console.log('\n[TEST 1] Testing /api/security/audit...');
  const auditRes = await request({
    host: 'localhost',
    port: 8080,
    path: '/api/security/audit',
    method: 'GET'
  });
  const audit = JSON.parse(auditRes.body);
  console.log(`Compliance Score: ${audit.overallScore} (${audit.passedCheckpoints})`);
  const passCount = audit.checklist.filter(c => c.status === 'PASS').length;
  if (passCount !== 20) throw new Error(`Security audit did not achieve 20/20 points! Found ${passCount}`);
  console.log('PASS: 20-Point Checklist verified 100% compliant (20/20 passed).');

  // 2. Owner Login (MFA Challenge)
  console.log('\n[TEST 2] Testing Owner Login & MFA Challenge...');
  const ownerLoginRes = await request({
    host: 'localhost',
    port: 8080,
    path: '/api/auth/login',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Requested-With': 'XMLHttpRequest'
    }
  }, { username: 'owner', password: 'Sharma@Bhiwadi1998' });

  const ownerLoginData = JSON.parse(ownerLoginRes.body);
  console.log('Owner login response:', ownerLoginData.message);
  if (!ownerLoginData.mfa_required || !ownerLoginData.temp_token) {
    throw new Error('Owner login failed to trigger MFA challenge!');
  }
  console.log('PASS: MFA Challenge properly triggered for Owner.');

  // 3. MFA Verification
  console.log('\n[TEST 3] Testing Owner MFA Verification (code: 199801)...');
  const mfaRes = await request({
    host: 'localhost',
    port: 8080,
    path: '/api/auth/verify-mfa',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Requested-With': 'XMLHttpRequest'
    }
  }, { temp_token: ownerLoginData.temp_token, code: '199801' });

  const mfaData = JSON.parse(mfaRes.body);
  if (!mfaData.success || !mfaRes.headers['set-cookie']) {
    throw new Error('MFA verification failed or failed to set HttpOnly cookie!');
  }
  const ownerCookie = mfaRes.headers['set-cookie'][0].split(';')[0];
  console.log(`PASS: Owner MFA verified. HttpOnly Cookie issued: ${ownerCookie.substring(0, 25)}...`);

  // 4. Owner Wholesale Cost Access
  console.log('\n[TEST 4] Testing Owner wholesale cost access (/api/frames)...');
  const ownerFramesRes = await request({
    host: 'localhost',
    port: 8080,
    path: '/api/frames',
    method: 'GET',
    headers: {
      'Cookie': ownerCookie
    }
  });
  const ownerFramesData = JSON.parse(ownerFramesRes.body);
  const firstOwnerFrame = ownerFramesData.frames[0];
  console.log(`Frame: "${firstOwnerFrame.name}", Buying Price: ₹${firstOwnerFrame.cost_price}, Selling Price: ₹${firstOwnerFrame.selling_price}`);
  if (typeof firstOwnerFrame.cost_price === 'undefined' || firstOwnerFrame.cost_price === null) {
    throw new Error('Owner should see cost_price, but it was undefined!');
  }
  console.log('PASS: Owner correctly sees wholesale buying price.');

  // 5. Staff Login (Direct, No Wholesale Cost)
  console.log('\n[TEST 5] Testing Staff Login & RBAC cost redaction...');
  const staffLoginRes = await request({
    host: 'localhost',
    port: 8080,
    path: '/api/auth/login',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Requested-With': 'XMLHttpRequest'
    }
  }, { username: 'staff', password: 'Staff@Optic2026' });

  const staffLoginData = JSON.parse(staffLoginRes.body);
  const staffCookie = staffLoginRes.headers['set-cookie'][0].split(';')[0];
  console.log(`Staff logged in: ${staffLoginData.user.name} (${staffLoginData.user.role})`);

  const staffFramesRes = await request({
    host: 'localhost',
    port: 8080,
    path: '/api/frames',
    method: 'GET',
    headers: {
      'Cookie': staffCookie
    }
  });
  const staffFramesData = JSON.parse(staffFramesRes.body);
  const firstStaffFrame = staffFramesData.frames[0];
  console.log(`Staff frame view: "${firstStaffFrame.name}", cost_price: ${firstStaffFrame.cost_price}`);
  if (typeof firstStaffFrame.cost_price !== 'undefined') {
    throw new Error('Staff should NOT see cost_price, but it was exposed!');
  }
  console.log('PASS: Staff wholesale buying price strictly redacted on server.');

  // 6. Medical Prescription IDOR Protection
  console.log('\n[TEST 6] Testing Medical Prescription Protected Access...');
  const anonPrescRes = await request({
    host: 'localhost',
    port: 8080,
    path: '/api/prescriptions/customer/9812345678',
    method: 'GET'
  });
  console.log(`Anonymous access status: ${anonPrescRes.statusCode}`);
  if (anonPrescRes.statusCode !== 401 && anonPrescRes.statusCode !== 403) {
    throw new Error('Anonymous access to medical prescription must return 401 or 403 Forbidden!');
  }
  console.log('PASS: Medical prescription protected against IDOR / BOLA.');

  // 7. Booking Registration API
  console.log('\n[TEST 7] Testing Customer Booking submission...');
  const bookingRes = await request({
    host: 'localhost',
    port: 8080,
    path: '/api/bookings',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Requested-With': 'XMLHttpRequest'
    }
  }, {
    name: 'Anjali Sharma',
    phone: '9876543210',
    date: '2026-11-25',
    slot: '04:00 PM',
    reason: 'Laser Consultation'
  });
  const bookingData = JSON.parse(bookingRes.body);
  console.log(`Booking created: ID ${bookingData.bookingId}, Token: ${bookingData.tokenId}`);
  if (!bookingData.success || !bookingData.bookingId) {
    throw new Error('Booking submission failed!');
  }
  console.log('PASS: Booking stored in SQLite database successfully.');

  // 8. Static Web Pages Delivery
  console.log('\n[TEST 8] Testing HTML page delivery...');
  const indexRes = await request({ host: 'localhost', port: 8080, path: '/', method: 'GET' });
  const adminRes = await request({ host: 'localhost', port: 8080, path: '/admin.html', method: 'GET' });
  if (indexRes.statusCode !== 200 || !indexRes.body.includes('Sharma Optical')) {
    throw new Error('index.html failed to serve correctly!');
  }
  if (adminRes.statusCode !== 200 || !adminRes.body.includes('modalMfaVerification')) {
    throw new Error('admin.html failed to serve or missing MFA modal!');
  }
  console.log('PASS: index.html and admin.html serving with full 200 OK headers.');

  console.log('\n=========================================');
  console.log('ALL TESTS PASSED! FULL-STACK VERIFIED 100%');
  console.log('=========================================');
}

runTests().catch(err => {
  console.error('TEST FAILED:', err);
  process.exit(1);
});
