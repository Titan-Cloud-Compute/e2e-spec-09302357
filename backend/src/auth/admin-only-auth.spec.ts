/**
 * admin-only auth model contract (U: admin-only).
 *
 * Pins the HTTP contract after removing public signup:
 *   - POST /api/auth/signup                    → 404 (route deleted)
 *   - GET  /api/auth/registration-token/:token → 404 (route deleted)
 *   - POST /api/auth/login                     → 200, AuthService.login called
 *   - GET  /api/probe-admin, no cookie         → 401
 *   - GET  /api/probe-admin, USER jwt          → 403
 *   - GET  /api/probe-admin, ADMIN jwt         → 200
 */
import { Controller, Get, INestApplication } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { JwtModule, JwtService } from '@nestjs/jwt';
import { Test } from '@nestjs/testing';
import * as cookieParser from 'cookie-parser';
import * as request from 'supertest';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtAuthGuard } from './jwt-auth.guard';
import { RequireAdmin, RolesGuard } from './roles.guard';

/** Minimal probe controller decorated with @RequireAdmin() for guard contract tests. */
@Controller('api/probe-admin')
@RequireAdmin()
class ProbeAdminController {
  @Get()
  ok(): { ok: boolean } {
    return { ok: true };
  }
}

// Shared mutable mock so assertions can inspect call counts after requests.
const loginMock = jest.fn().mockResolvedValue({
  user: { id: 'u1', email: 'admin@demo.local', role: 'ADMIN' },
  token: 'signed-token',
});

describe('admin_only auth model (U: admin-only)', () => {
  let app: INestApplication;
  let jwtService: JwtService;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [JwtModule.register({ secret: 'test-secret' })],
      controllers: [AuthController, ProbeAdminController],
      providers: [
        {
          provide: AuthService,
          useValue: { login: loginMock },
        },
        { provide: APP_GUARD, useClass: JwtAuthGuard },
        { provide: APP_GUARD, useClass: RolesGuard },
      ],
    }).compile();

    app = moduleRef.createNestApplication();
    // cookieParser required so JwtAuthGuard can read req.cookies['session']
    app.use(cookieParser());
    await app.init();

    jwtService = moduleRef.get<JwtService>(JwtService);
  });

  afterAll(async () => {
    await app.close();
  });

  // ── removed routes ────────────────────────────────────────────────────────

  it('POST /api/auth/signup → 404 (public signup removed)', () =>
    request(app.getHttpServer())
      .post('/api/auth/signup')
      .send({ email: 'new@demo.local', password: 'Password1!', name: 'Test' })
      .expect(404));

  it('GET /api/auth/registration-token/<48-hex> → 404 (route removed)', () =>
    request(app.getHttpServer())
      .get('/api/auth/registration-token/' + 'a'.repeat(48))
      .expect(404));

  // ── login still works ─────────────────────────────────────────────────────

  it('POST /api/auth/login → 200 and AuthService.login was called', async () => {
    loginMock.mockClear();
    await request(app.getHttpServer())
      .post('/api/auth/login')
      .send({ email: 'admin@demo.local', password: 'secret' })
      .expect(200);
    expect(loginMock).toHaveBeenCalledTimes(1);
  });

  // ── @RequireAdmin guard contract ──────────────────────────────────────────

  it('GET /api/probe-admin with no cookie → 401', () =>
    request(app.getHttpServer()).get('/api/probe-admin').expect(401));

  it('GET /api/probe-admin with USER session cookie → 403', async () => {
    const token = await jwtService.signAsync({
      userId: 'u1',
      role: 'USER',
      firmId: null,
    });
    await request(app.getHttpServer())
      .get('/api/probe-admin')
      .set('Cookie', `session=${token}`)
      .expect(403);
  });

  it('GET /api/probe-admin with ADMIN session cookie → 200', async () => {
    const token = await jwtService.signAsync({
      userId: 'u1',
      role: 'ADMIN',
      firmId: null,
    });
    await request(app.getHttpServer())
      .get('/api/probe-admin')
      .set('Cookie', `session=${token}`)
      .expect(200);
  });
});
