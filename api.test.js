const request = require('supertest');
const appUrl = process.env.TEST_APP_URL || 'http://localhost:4000';

describe('Basic API', ()=>{
  test('health endpoint', async ()=>{
    const res = await request(appUrl).get('/health');
    expect(res.statusCode).toBe(200);
    expect(res.body).toHaveProperty('ok', true);
  }, 10000);

  test('search empty returns 200', async ()=>{
    const res = await request(appUrl).get('/search?q=test');
    expect(res.statusCode).toBe(200);
  });
});
