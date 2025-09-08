import { Entity, PrimaryGeneratedColumn, Column, ManyToOne, 
JoinColumn, Index, CreateDateColumn, UpdateDateColumn} from 'typeorm';
import { User } from '../../users/users.entity';
  
  export enum RefreshPlatform {
    WEB = 'web',
    IOS = 'ios',
    ANDROID = 'android',
    DESKTOP = 'desktop',
  }
  
  /**
   * Notas:
   * - tokenLookupHash (HMAC-SHA256(token+pepper)) = busca rápida por índice (UNIQUE).
   * - tokenHash (Argon2id(token+pepper)) = verificação forte.
   * - familyId/parentId/replacedById = rotação e reuse detection por dispositivo/sessão.
   * - Índices para consultas performáticas (ativos por usuário, expiração, família).
   */
  @Index('idx_refresh_active_user', ['userId', 'revokedAt'])
  @Index('idx_refresh_expires_at', ['expiresAt'])
  @Index('idx_refresh_family', ['familyId'])
  @Index('idx_refresh_user_revoked', ['userId', 'revokedAt'])
  @Entity({ name: 'refresh_tokens' })
  export class RefreshToken {
    @PrimaryGeneratedColumn('uuid')
    id!: string;
  
    // ---- Relação com User ----
    @Column('uuid', { name: 'user_id' })
    @Index('idx_refresh_user')
    userId!: string;
  
    @ManyToOne(() => User, { onDelete: 'CASCADE' })
    @JoinColumn({ name: 'user_id' })
    user!: User;
  
    // ---- Identificadores e hashes ----
    @Column({ name: 'token_lookup_hash', type: 'varchar', length: 128, unique: true })
    tokenLookupHash!: string; // HMAC-SHA256(token+pepper) em hex/base64
  
    @Column({ name: 'token_hash', type: 'varchar', length: 255 })
    tokenHash!: string; // Argon2id(token+pepper)
  
    @Column('uuid', { name: 'family_id' })
    familyId!: string; // sessão/dispositivo (revogação em cadeia)
  
    @Column('uuid', { name: 'parent_id', nullable: true })
    parentId: string | null = null; // encadeia o anterior (rotação)
  
    @Column('uuid', { name: 'replaced_by_id', nullable: true })
    replacedById: string | null = null; // aponta para o próximo (rotação)
  
    // ---- Auditoria e janela de validade ----
    @CreateDateColumn({ name: 'created_at' })
    createdAt!: Date;
  
    @Column({ name: 'issued_at', type: 'timestamp', default: () => 'now()' })
    issuedAt!: Date;
  
    @Column({ name: 'expires_at', type: 'timestamp' })
    expiresAt!: Date;
  
    @UpdateDateColumn({ name: 'updated_at' })
    updatedAt!: Date;
  
    @Column({ name: 'last_used_at', type: 'timestamp', nullable: true })
    lastUsedAt: Date | null = null;
  
    // ---- Revogação e segurança ----
    @Column({ name: 'revoked_at', type: 'timestamp', nullable: true })
    revokedAt: Date | null = null;
  
    @Column({ name: 'revoked_reason', type: 'varchar', length: 128, nullable: true })
    revokedReason: string | null = null;
  
    @Column({ name: 'compromised_at', type: 'timestamp', nullable: true })
    compromisedAt: Date | null = null; // reuse detection/incidente
  
    // ---- Device tracking (opcionais; atenção LGPD) ----
    @Column({ name: 'device_id', type: 'varchar', length: 64, nullable: true })
    deviceId: string | null = null;
  
    @Column({
      name: 'platform',
      type: 'enum',
      enum: RefreshPlatform,
      nullable: true,
    })
    platform: RefreshPlatform | null = null;
  
    @Column({ name: 'user_agent', type: 'varchar', length: 512, nullable: true })
    userAgent: string | null = null;
  
    @Column({ name: 'created_by_ip', type: 'varchar', length: 64, nullable: true })
    createdByIp: string | null = null;
  
    @Column({ name: 'last_used_ip', type: 'varchar', length: 64, nullable: true })
    lastUsedIp: string | null = null;
  
    // ---- Extensões livres sem migrar schema ----
    @Column({ type: 'jsonb', nullable: true })
    metadata: Record<string, unknown> | null = null;
  }
  