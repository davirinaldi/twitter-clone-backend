import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { DataSource, Repository, IsNull } from 'typeorm';
import { RefreshToken } from '../entities/refresh-token.entity';
import * as crypto from 'crypto';
import * as argon2 from 'argon2';

type IssueContext = {
  ip?: string | null;
  userAgent?: string | null;
  platform?: RefreshToken['platform'];
  deviceId?: string | null;
  metadata?: Record<string, unknown> | null;
  familyId?: string | null;        // se não vier, cria nova família
  ttlMs?: number;                  // default configurável
  parentId?: string | null;        // usado internamente na rotação
};

@Injectable()
export class RefreshTokenService {
  private readonly defaultTtlMs =
    Number(process.env.REFRESH_TTL_MS ?? 30 * 24 * 60 * 60 * 1000); // 30d
  private readonly pepper = process.env.REFRESH_TOKEN_PEPPER ?? 'change-me';

  constructor(
    @InjectRepository(RefreshToken)
    private readonly repo: Repository<RefreshToken>,
    private readonly ds: DataSource,
  ) {}

  // ---------- Helpers de segurança ----------

  /** token aleatório seguro (base64url) */
  private generateRawToken(size = 64): string {
    return crypto.randomBytes(size).toString('base64url');
  }

  /** HMAC-SHA256(token) com pepper como chave → busca rápida por índice UNIQUE */
  private makeLookupHash(raw: string): string {
    return crypto.createHmac('sha256', this.pepper).update(raw).digest('hex');
  }

  /** Argon2id(token+pepper) → verificação forte */
  private async hashStrong(raw: string): Promise<string> {
    return argon2.hash(raw + this.pepper, {
      type: argon2.argon2id,
      timeCost: 3,
      memoryCost: 1 << 15, // 32MB
      parallelism: 1,
    });
  }

  private async verifyStrong(raw: string, strongHash: string): Promise<boolean> {
    try {
      return await argon2.verify(strongHash, raw + this.pepper);
    } catch {
      return false;
    }
  }

  // ---------- Emissão / Rotação ----------

  /** Emite um novo refresh token (novo device/sessão ou dentro de uma família existente). */
  async issue(userId: string, ctx: IssueContext = {}) {
    const raw = this.generateRawToken();
    const tokenLookupHash = this.makeLookupHash(raw);
    const tokenHash = await this.hashStrong(raw);
    const familyId = ctx.familyId ?? crypto.randomUUID();
    const ttlMs = ctx.ttlMs ?? this.defaultTtlMs;

    const now = new Date();
    const entity = this.repo.create({
      userId,
      tokenLookupHash,
      tokenHash,
      familyId,
      parentId: ctx.parentId ?? null,
      replacedById: null,
      createdAt: now,
      issuedAt: now,
      expiresAt: new Date(now.getTime() + ttlMs),
      updatedAt: now,
      lastUsedAt: null,
      revokedAt: null,
      revokedReason: null,
      compromisedAt: null,
      deviceId: ctx.deviceId ?? null,
      platform: ctx.platform ?? null,
      userAgent: ctx.userAgent ?? null,
      createdByIp: ctx.ip ?? null,
      lastUsedIp: null,
      metadata: ctx.metadata ?? null,
    });

    const saved = await this.repo.save(entity);
    return {
      raw,                    // devolver ao cliente em cookie httpOnly/secure
      token: saved,           // registro salvo
    };
  }

  /**
   * Verifica e rotaciona um refresh token (single-use).
   * Se detectar reutilização, compromete e revoga toda a família.
   */
  async verifyAndRotate(userId: string, presentedRaw: string, ip?: string | null, userAgent?: string | null) {
    const lookup = this.makeLookupHash(presentedRaw);

    // Busca direta por índice UNIQUE
    const current = await this.repo.findOne({ where: { tokenLookupHash: lookup } });

    // Token inexistente ou de outro user → inválido
    if (!current || current.userId !== userId) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    // Expirado ou revogado
    const now = new Date();
    if (current.expiresAt <= now || current.revokedAt) {
      throw new UnauthorizedException('Expired or revoked refresh token');
    }

    // Verificação forte (Argon2id)
    const ok = await this.verifyStrong(presentedRaw, current.tokenHash);
    if (!ok) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    // Reuse detection: se já foi usado/rotacionado antes, comprometido.
    const alreadyUsed = !!current.lastUsedAt || !!current.replacedById;
    if (alreadyUsed) {
      await this.compromiseFamily(current.userId, current.familyId, 'reuse-detected');
      throw new UnauthorizedException('Refresh token reuse detected');
    }

    // Marca uso e rotaciona (single-use)
    const newIssue = await this.issue(userId, {
      ip,
      userAgent,
      platform: current.platform,
      deviceId: current.deviceId,
      familyId: current.familyId,     // mantém a mesma família (mesmo device)
      ttlMs: current.expiresAt.getTime() - now.getTime(), // conserva janela (ou renove, se quiser)
      parentId: current.id,
      metadata: current.metadata,
    });

    // Atualiza o token atual: usado, revogado e apontando para o novo
    await this.repo.update(current.id, {
      lastUsedAt: now,
      lastUsedIp: ip ?? null,
      revokedAt: now,
      revokedReason: 'rotated',
      replacedById: newIssue.token.id,
      updatedAt: now,
    });

    return {
      raw: newIssue.raw,
      accessAdvice: 'rotate', // dica para camada superior saber que deve atualizar cookie
      familyId: current.familyId,
      tokenId: newIssue.token.id,
      expiresAt: newIssue.token.expiresAt,
    };
  }

  // ---------- Revogações / Comprometimento ----------

  /** Revoga um token específico. */
  async revokeToken(tokenId: string, reason: string = 'manual-revoke') {
    await this.repo.update(tokenId, {
      revokedAt: new Date(),
      revokedReason: reason,
    });
  }

  /** Revoga toda a família (logout daquele dispositivo/sessão). */
  async revokeFamily(userId: string, familyId: string, reason: string = 'family-revoke') {
    await this.repo
      .createQueryBuilder()
      .update(RefreshToken)
      .set({ revokedAt: () => 'now()', revokedReason: reason })
      .where('user_id = :userId AND family_id = :familyId AND revoked_at IS NULL', { userId, familyId })
      .execute();
  }

  /** Marca como comprometida e revoga toda a família (reuse detection). */
  private async compromiseFamily(userId: string, familyId: string, reason: string) {
    await this.ds.transaction(async (trx) => {
      await trx
        .createQueryBuilder()
        .update(RefreshToken)
        .set({ compromisedAt: () => 'now()' })
        .where('user_id = :userId AND family_id = :familyId AND compromised_at IS NULL', { userId, familyId })
        .execute();

      await trx
        .createQueryBuilder()
        .update(RefreshToken)
        .set({ revokedAt: () => 'now()', revokedReason: reason })
        .where('user_id = :userId AND family_id = :familyId AND revoked_at IS NULL', { userId, familyId })
        .execute();
    });
  }

  /** Logout global: revoga todos os refresh tokens do usuário. */
  async revokeAll(userId: string, reason: string = 'global-logout') {
    await this.repo
      .createQueryBuilder()
      .update(RefreshToken)
      .set({ revokedAt: () => 'now()', revokedReason: reason })
      .where('user_id = :userId AND revoked_at IS NULL', { userId })
      .execute();
  }

  // ---------- Manutenção ----------

  /** Remove tokens expirados (agendar em cron diário). */
  async purgeExpired(before: Date = new Date()) {
    await this.repo
      .createQueryBuilder()
      .delete()
      .from(RefreshToken)
      .where('expires_at < :before', { before })
      .execute();
  }

  // ---------- Consultas úteis ----------

  async listActiveByUser(userId: string) {
    return this.repo.find({
      where: { userId, revokedAt: IsNull() },
      order: { createdAt: 'DESC' },
      take: 100,
    });
  }

  async listFamily(userId: string, familyId: string) {
    return this.repo.find({
      where: { userId, familyId },
      order: { issuedAt: 'ASC' },
    });
  }
}
