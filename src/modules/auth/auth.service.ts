import { Injectable, NotFoundException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from '../users/users.service';
import { AuthResponseDto } from './dto/auth-response.dto';
import { User } from '../users/users.entity';
import { UserPublicDto } from '../users/dto/user-response.dto';
import { UserMeDto } from '../users/dto/user-me.dto';
import { RefreshTokenService } from './services/token-management.service';
import * as bcrypt from 'bcrypt';

  @Injectable()
  export class AuthService {
    constructor(
      private readonly usersService: UsersService,
      private readonly jwtService: JwtService,
      private readonly refreshTokenService: RefreshTokenService,
    ) {}

    // 1. validateUser() - Para LocalStrategy usar
    async validateUser(identifier: string, password: string): Promise<User | null> {
        const user = await this.usersService.findByEmailOrUsername(identifier);

    // Evita enumerar usuário/senha
    if (!user || !user.isActive) {
      return null;
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return null;
    }

    // Retorna somente dados seguros
    return user;

    }

    // 2. login() - Gerar tokens híbridos (JWT access + DB refresh)
    async login(user: User, context?: { ip?: string; userAgent?: string; platform?: string }): Promise<AuthResponseDto> {
        const payload = {
            sub: user.id,
            username: user.username,
          };
      
          // Access token JWT (stateless, rápido)
          const access_token = this.jwtService.sign(payload, {
            expiresIn: process.env.JWT_ACCESS_EXPIRATION || '30m',
          });
      
          // Refresh token seguro (database-based com sua arquitetura)
          const refreshResult = await this.refreshTokenService.issue(user.id, {
            ip: context?.ip,
            userAgent: context?.userAgent,
            platform: context?.platform as any, // cast para RefreshPlatform
            // Nova família para cada login
          });
      
          // Mapeia só dados públicos do usuário
          const userPublic: UserPublicDto = {
            id: user.id,
            username: user.username,
          };
      
          return {
            access_token,
            refresh_token: refreshResult.raw, // Token criptograficamente seguro
            user: userPublic,
          };
    }
    // 3. refresh() - Renovar tokens usando arquitetura híbrida
    async refresh(userId: string, refreshToken: string, context?: { ip?: string; userAgent?: string }): Promise<AuthResponseDto> {
      // Valida e rotaciona o refresh token (database-based)
      const rotationResult = await this.refreshTokenService.verifyAndRotate(
        userId, 
        refreshToken, 
        context?.ip, 
        context?.userAgent
      );

      // Gera novo access token JWT
      const user = await this.usersService.findOne(userId);
      if (!user || !user.isActive) {
        throw new NotFoundException('User not found or inactive');
      }

      const payload = {
        sub: user.id,
        username: user.username,
      };

      const access_token = this.jwtService.sign(payload, {
        expiresIn: process.env.JWT_ACCESS_EXPIRATION || '30m',
      });

      const userPublic: UserPublicDto = {
        id: user.id,
        username: user.username,
      };

      return {
        access_token,
        refresh_token: rotationResult.raw, // Novo refresh token rotacionado
        user: userPublic,
      };
    }

    async getMe(userId: string): Promise<UserMeDto> {
      const user = await this.usersService.findOne(userId);
      if (!user) {
        throw new NotFoundException(`Usuário com id ${userId} não encontrado`);
      }
      const userMe: UserMeDto = {
        id: user.id,
        username: user.username,
        email: user.email,
        createdAt: user.createdAt
      };
      return userMe;

    }

  }