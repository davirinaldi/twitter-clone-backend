import { Injectable, NotFoundException, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from '../users/users.service';
import { AuthResponseDto } from './dto/auth-response.dto';
import { User } from '../users/users.entity';
import { UserPublicDto } from '../users/dto/user-response.dto';
import { UserMeDto } from '../users/dto/user-me.dto';
import { RefreshTokenService } from './services/token-management.service';
import { LogoutResponseDto } from './dto/logout-response.dto';
import { DataSource } from 'typeorm';
import * as bcrypt from 'bcrypt';

  @Injectable()
  export class AuthService {
    private readonly logger = new Logger(AuthService.name);

    constructor(
      private readonly usersService: UsersService,
      private readonly jwtService: JwtService,
      private readonly refreshTokenService: RefreshTokenService,
      private readonly dataSource: DataSource,
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
      // Refresh token seguro PRIMEIRO (database-based com sua arquitetura)
      const refreshResult = await this.refreshTokenService.issue(user.id, {
        ip: context?.ip,
        userAgent: context?.userAgent,
        platform: context?.platform as any, // cast para RefreshPlatform
        // Nova família para cada login
      });

      const payload = {
        sub: user.id,
        username: user.username,
        tokenId: refreshResult.token.id,       // ← ADICIONAR REFERÊNCIA
        familyId: refreshResult.token.familyId // ← PARA LOGOUT CONTEXT
      };
  
      // Access token JWT com referência ao refresh token
      const access_token = this.jwtService.sign(payload, {
        expiresIn: process.env.JWT_ACCESS_EXPIRATION || '30m',
      });
      
          // Mapeia só dados públicos do usuário
          const userPublic: UserPublicDto = {
            id: user.id,
            username: user.username,
            role: user.role,
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
        role: user.role,
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
        createdAt: user.createdAt,
        role: user.role
      };
      return userMe;

    }
    // 4. logout() - Enterprise logout com transaction e error handling
    async logout(userId: string, currentJwt: string, logoutAll = false): Promise<LogoutResponseDto> {
      const startTime = Date.now();
      
      try {
        return await this.dataSource.transaction(async (manager) => {
          // 1. Decode JWT para extrair context da sessão atual
          const jwtPayload = this.jwtService.decode(currentJwt) as any;
          const currentTokenId = jwtPayload?.tokenId;
          
          let revokedCount = 0;
          
          if (logoutAll) {
            // Logout global: revoga TODAS as families do usuário
            this.logger.log(`Global logout requested for user: ${userId}`);
            revokedCount = await this.refreshTokenService.revokeAll(userId, 'user-logout-all');
            
          } else {
            // Logout single device: revoga apenas family atual
            if (currentTokenId) {
              const currentToken = await this.refreshTokenService.findByTokenId(currentTokenId);
              if (currentToken?.familyId) {
                await this.refreshTokenService.revokeFamily(userId, currentToken.familyId, 'user-logout');
                revokedCount = 1;
                this.logger.log(`Single device logout for user: ${userId}, family: ${currentToken.familyId}`);
              }
            }
          }
          
          // Sempre retorna sucesso (timing attack prevention)
          const response: LogoutResponseDto = {
            message: logoutAll ? "Logged out from all devices" : "Logged out successfully",
            loggedOutDevices: revokedCount,
            timestamp: new Date().toISOString()
          };
          
          return response;
        });
        
      } catch (error) {
        // Log error mas NUNCA exponha ao client (security)
        this.logger.error(`Logout error for user ${userId}:`, error);
        
        // Sempre retorna "sucesso" mesmo com erro (security by obscurity)
        return {
          message: "Logged out successfully",
          loggedOutDevices: 0,
          timestamp: new Date().toISOString()
        };
      } finally {
        // Constant-time response (timing attack prevention)
        const elapsed = Date.now() - startTime;
        const minTime = 200; // 200ms minimum
        if (elapsed < minTime) {
          await new Promise(resolve => setTimeout(resolve, minTime - elapsed));
        }
      }
    }


  }