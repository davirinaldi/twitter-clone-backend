import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from '../users/users.service';
import { AuthResponseDto } from './dto/auth-response.dto';
import { User } from '../users/users.entity';
import { UserPublicDto } from '../users/dto/user-response.dto';
import * as bcrypt from 'bcrypt';

  @Injectable()
  export class AuthService {
    constructor(
      private readonly usersService: UsersService,
      private readonly jwtService: JwtService,
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

    // 2. login() - Gerar tokens JWT
    async login(user: User): Promise<AuthResponseDto> {
        const payload = {
            sub: user.id,
            username: user.username,
          };
      
          // Access token curto (ex: 30 min, definido no .env ou no módulo Jwt)
          const access_token = this.jwtService.sign(payload, {
            expiresIn: process.env.JWT_ACCESS_EXPIRATION || '30m',
          });
      
          // Refresh token longo (ex: 30 dias)
          const refresh_token = this.jwtService.sign(payload, {
            expiresIn: process.env.JWT_REFRESH_EXPIRATION || '30d',
          });
      
          // Mapeia só dados públicos do usuário
          const userPublic: UserPublicDto = {
            id: user.id,
            username: user.username,
          };
      
          return {
            access_token,
            refresh_token,
            user: userPublic,
          };
    }
  }